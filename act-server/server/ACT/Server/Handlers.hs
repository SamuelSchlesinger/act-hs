{-# LANGUAGE CPP #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeApplications #-}
module ACT.Server.Handlers
  ( server
  ) where

import ACT.Server.API (ACTAPI)
import ACT.Server.Crypto (computeRequestContext, issuerKeyId, truncatedKeyId)
import ACT.Server.DB (checkAndStoreNullifier)
import ACT.Server.Types (ServerState(..), IssuerDirectory(..))
import ACT.Server.WireFormat
  ( parseTokenRequest, parseToken
  , encodeTokenResponse, encodeTokenChallenge, tokenType
  )

import Crypto.AnonymousCreditTokens
  ( L16, issue, refund
  , spendProofNullifier, spendProofCharge
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

  -- Validate spend charge is > 0
  let charge = spendProofCharge proof
  case scalarToWord64 charge of
    Just 0 -> throwError $ err422 { errBody = "spend charge must be > 0" }
    _      -> return ()

  -- Atomic nullifier check
  isNew <- liftIO $ checkAndStoreNullifier (ssConn st) nullifierBytes
  if not isNew
    then throwError err409 { errBody = "duplicate nullifier (double-spend)" }
    else return ()

  -- Verify spend proof and create refund
  result <- liftIO $ refund @L16 (ssPrivateKey st) (ssParams st) proof
#else
#error "act-server requires ACT_L16"
#endif

  case result of
    Right (Refund refundBytes) ->
      return $ LBS.fromStrict refundBytes
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
  }

encodeUtf8' :: String -> BS.ByteString
encodeUtf8' = BS.pack . map (fromIntegral . fromEnum)

decodeUtf8' :: BS.ByteString -> Text
decodeUtf8' = TE.decodeUtf8
