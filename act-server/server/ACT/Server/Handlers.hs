{-# LANGUAGE CPP #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeApplications #-}
module ACT.Server.Handlers
  ( server
  ) where

import ACT.API (ACTAPI)
import ACT.Crypto (computeRequestContext, issuerKeyId, truncatedKeyId)
import ACT.Server.DB (checkAndStoreNullifier, lookupStoredRefund)
import ACT.Server.Types (ServerState(..), IssuerDirectory(..))
import ACT.WireFormat
  ( parseTokenRequest, parseToken
  , encodeTokenResponse, encodeTokenChallenge, tokenType
  )

import Crypto.AnonymousCreditTokens
  ( L16, issue, refund
  , spendProofNullifier, spendProofCharge, spendProofContext
  )
import Crypto.AnonymousCreditTokens.Types
  ( PublicKey(..)
  , IssuanceRequest(..), IssuanceResponse(..)
  , SpendProof(..), Refund(..), Scalar(..)
  , scalarFromWord64, scalarToWord64
  )
import Crypto.Hash.SHA256 (hash)

import Control.Monad.IO.Class (liftIO)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as B16
import qualified Data.ByteString.Lazy as LBS
import Data.Text (Text)
import qualified Data.Text.Encoding as TE
import Servant

server :: ServerState -> Server ACTAPI
server st = handleTokenRequest st
       :<|> handleTokenRedeem st
       :<|> handleIssuerDirectory st

handleTokenRequest :: ServerState -> LBS.ByteString -> Handler LBS.ByteString
handleTokenRequest st reqBody = do
  let bs = LBS.toStrict reqBody
  -- Parse TokenRequest
  (truncKeyId, encodedRequest) <- case parseTokenRequest bs of
    Left err -> throwError $ err422 { errBody = LBS.fromStrict (encodeUtf8' err) }
    Right r  -> return r

  -- Validate truncated key ID
  let expectedTruncKeyId = truncatedKeyId (ssPublicKey st)
  if truncKeyId /= expectedTruncKeyId
    then throwError $ err422 { errBody = "truncated_key_id mismatch" }
    else return ()

  -- Compute request_context
  let keyId = issuerKeyId (ssPublicKey st)
      ctx = computeRequestContext
              (ssIssuerName st)
              (ssOriginInfo st)
              (ssCredentialContext st)
              keyId

  -- Issue credentials
  let issuanceReq = IssuanceRequest encodedRequest
      credits = scalarFromWord64 (ssInitialCredits st)
#ifdef ACT_L16
  result <- liftIO $ issue @L16
    (ssPrivateKey st)
    (ssParams st)
    issuanceReq
    credits
    ctx
#else
#error "act-server requires ACT_L16"
#endif

  case result of
    Right (IssuanceResponse respBytes) ->
      return $ LBS.fromStrict (encodeTokenResponse respBytes)
    Left err ->
      throwError $ err422 { errBody = LBS.fromStrict (encodeUtf8' (show err)) }

handleTokenRedeem :: ServerState -> LBS.ByteString -> Handler LBS.ByteString
handleTokenRedeem st tokenBody = do
  let bs = LBS.toStrict tokenBody
  -- Parse Token
  (challengeDigest, issuerKeyIdBytes, encodedSpendProof) <- case parseToken bs of
    Left err -> throwError $ err422 { errBody = LBS.fromStrict (encodeUtf8' err) }
    Right r  -> return r

  -- Validate issuer_key_id
  let expectedKeyId = issuerKeyId (ssPublicKey st)
  if issuerKeyIdBytes /= expectedKeyId
    then throwError $ err422 { errBody = "issuer_key_id mismatch" }
    else return ()

  -- Verify challenge_digest matches expected
  let expectedChallenge = encodeTokenChallenge
        (ssIssuerName st)
        BS.empty  -- redemption_context (empty for now)
        (ssOriginInfo st)
        (ssCredentialContext st)
      expectedDigest = hash expectedChallenge
  if challengeDigest /= expectedDigest
    then throwError $ err422 { errBody = "challenge_digest mismatch" }
    else return ()

#ifdef ACT_L16
  let proof = SpendProof encodedSpendProof :: SpendProof L16
      Scalar nullifierBytes = spendProofNullifier proof
      proofHash = hash encodedSpendProof

  -- Verify spendProofContext matches expected request_context
  let expectedCtx = computeRequestContext
                      (ssIssuerName st)
                      (ssOriginInfo st)
                      (ssCredentialContext st)
                      expectedKeyId
      proofCtx = spendProofContext proof
  if proofCtx /= expectedCtx
    then throwError $ err422 { errBody = "request_context mismatch" }
    else return ()

  -- Verify spend charge matches expected cost
  let charge = spendProofCharge proof
      expectedCost = scalarFromWord64 (ssDefaultCost st)
  case scalarToWord64 charge of
    Just 0 -> throwError $ err422 { errBody = "spend charge must be > 0" }
    _      -> return ()
  if charge /= expectedCost
    then throwError $ err422 { errBody = "spend charge does not match expected cost" }
    else return ()

  -- Check for idempotent retry: if nullifier already exists, verify proof and return stored refund
  let Scalar ctxBytes = expectedCtx
  existingRefund <- liftIO $ lookupStoredRefund (ssConn st) nullifierBytes
  case existingRefund of
    Just (storedProofHash, storedRefundBytes)
      | storedProofHash == proofHash ->
          return $ LBS.fromStrict storedRefundBytes
      | otherwise ->
          throwError err409 { errBody = "duplicate nullifier (double-spend)" }
    Nothing -> do
      -- Verify spend proof and create refund
      result <- liftIO $ refund @L16 (ssPrivateKey st) (ssParams st) proof
#else
#error "act-server requires ACT_L16"
#endif

      case result of
        Right (Refund refundBytes) -> do
          -- Atomically store nullifier with context, proof hash, and refund data
          isNew <- liftIO $ checkAndStoreNullifier (ssConn st) nullifierBytes ctxBytes proofHash refundBytes
          if not isNew
            -- Race condition: another request stored the nullifier between our check and insert
            then do
              storedRefund <- liftIO $ lookupStoredRefund (ssConn st) nullifierBytes
              case storedRefund of
                Just (ph, rb)
                  | ph == proofHash -> return $ LBS.fromStrict rb
                  | otherwise -> throwError err409 { errBody = "duplicate nullifier (double-spend)" }
                Nothing -> throwError err409 { errBody = "duplicate nullifier (double-spend)" }
            else return $ LBS.fromStrict refundBytes
        Left err ->
          throwError $ err422 { errBody = LBS.fromStrict (encodeUtf8' (show err)) }

handleIssuerDirectory :: ServerState -> Handler IssuerDirectory
handleIssuerDirectory st = return IssuerDirectory
  { idTokenType        = tokenType
  , idIssuerName       = decodeUtf8' (ssIssuerName st)
  , idOriginInfo       = decodeUtf8' (ssOriginInfo st)
  , idCredentialContext = TE.decodeUtf8 (B16.encode (ssCredentialContext st))
  , idIssuerKeyId      = TE.decodeUtf8 (B16.encode (issuerKeyId (ssPublicKey st)))
  , idPublicKey        = TE.decodeUtf8 (B16.encode (let PublicKey b = ssPublicKey st in b))
  , idInitialCredits   = ssInitialCredits st
  , idDefaultCost      = ssDefaultCost st
  }

encodeUtf8' :: String -> BS.ByteString
encodeUtf8' = BS.pack . map (fromIntegral . fromEnum)

decodeUtf8' :: BS.ByteString -> Text
decodeUtf8' = TE.decodeUtf8
