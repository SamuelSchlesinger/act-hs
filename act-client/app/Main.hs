{-# LANGUAGE CPP #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeApplications #-}
module Main (main) where

import ACT.Client.Config (Command(..), InitOpts(..), SpendOpts(..), parseCommand)
import ACT.Client.DB
  ( ServerConfig(..)
  , initClientDB, saveServerConfig, loadServerConfig
  , saveCredential, loadActiveCredential
  )
import ACT.Client.HTTP (fetchIssuerDirectory, requestCredential, redeemToken)
import ACT.Crypto (issuerKeyId, truncatedKeyId)
import ACT.Types (IssuerDirectory(..))
import ACT.WireFormat (encodeTokenRequest, encodeToken, encodeTokenChallenge)

import Crypto.AnonymousCreditTokens
import Crypto.Hash.SHA256 (hash)

import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as B16
import qualified Data.Text.Encoding as TE
import Database.SQLite.Simple (open)
import Network.HTTP.Client (newManager)
import Network.HTTP.Client.TLS (tlsManagerSettings)
import Servant.Client (mkClientEnv, parseBaseUrl)

main :: IO ()
main = do
  cmd <- parseCommand
  case cmd of
    Init opts   -> runInit opts
    Issue dbPath -> runIssue dbPath
    Spend opts  -> runSpend opts
    Status dbPath -> runStatus dbPath

runInit :: InitOpts -> IO ()
runInit opts = do
  conn <- open (initDBPath opts)
  initClientDB conn

  mgr <- newManager tlsManagerSettings
  baseUrl <- parseBaseUrl (initServerUrl opts)
  let env = mkClientEnv mgr baseUrl

  dir <- fetchIssuerDirectory env

  -- Decode hex-encoded fields from the directory
  let pkBytes = decodeHex (TE.encodeUtf8 (idPublicKey dir))
      keyIdBytes = decodeHex (TE.encodeUtf8 (idIssuerKeyId dir))
      credCtxBytes = decodeHex (TE.encodeUtf8 (idCredentialContext dir))
      issuerNameBytes = TE.encodeUtf8 (idIssuerName dir)
      originInfoBytes = TE.encodeUtf8 (idOriginInfo dir)

  let sc = ServerConfig
        { scServerUrl        = initServerUrl opts
        , scIssuerName       = issuerNameBytes
        , scOriginInfo       = originInfoBytes
        , scCredentialContext = credCtxBytes
        , scIssuerKeyId      = keyIdBytes
        , scPublicKey        = pkBytes
        , scInitialCredits   = idInitialCredits dir
        , scDefaultCost      = idDefaultCost dir
        , scParamsOrg        = initParamsOrg opts
        , scParamsSvc        = initParamsSvc opts
        , scParamsDep        = initParamsDep opts
        , scParamsVer        = initParamsVer opts
        }

  saveServerConfig conn sc
  putStrLn "Initialized. Server config saved."
  putStrLn $ "  Issuer: " ++ show (idIssuerName dir)
  putStrLn $ "  Initial credits: " ++ show (idInitialCredits dir)
  putStrLn $ "  Default cost: " ++ show (idDefaultCost dir)

runIssue :: FilePath -> IO ()
runIssue dbPath = do
  conn <- open dbPath
  initClientDB conn

  sc <- loadServerConfig conn >>= maybe (fail "Not initialized. Run 'init' first.") return

  mgr <- newManager tlsManagerSettings
  baseUrl <- parseBaseUrl (scServerUrl sc)
  let env = mkClientEnv mgr baseUrl

  params <- newParams (scParamsOrg sc) (scParamsSvc sc) (scParamsDep sc) (scParamsVer sc)
  let pk = PublicKey (scPublicKey sc)

  -- Generate pre-issuance and request
  preIss <- generatePreIssuance
  req <- issuanceRequest preIss params
  let IssuanceRequest reqBytes = req
      truncKeyId = truncatedKeyId pk
      tokenReqBytes = encodeTokenRequest truncKeyId reqBytes

  -- Send to server
  respBytes <- requestCredential env tokenReqBytes

  -- Finalize credential
  tokenResult <- toCreditToken preIss params pk req (IssuanceResponse respBytes)
  case tokenResult of
    Right token -> do
      let credits = creditTokenCredits token
          CreditToken tokenBytes = token
      case scalarToWord64 credits of
        Just c -> do
          saveCredential conn tokenBytes c
          putStrLn $ "Credential issued with " ++ show c ++ " credits."
        Nothing -> do
          saveCredential conn tokenBytes 0
          putStrLn "Credential issued (credits exceed Word64 range)."
    Left err -> fail $ "Failed to finalize credential: " ++ show err

runSpend :: SpendOpts -> IO ()
runSpend opts = do
  conn <- open (spendDBPath opts)
  initClientDB conn

  sc <- loadServerConfig conn >>= maybe (fail "Not initialized. Run 'init' first.") return

  (tokenBytes, _) <- loadActiveCredential conn
    >>= maybe (fail "No active credential. Run 'issue' first.") return

  let token = CreditToken tokenBytes
      pk = PublicKey (scPublicKey sc)
      cost = maybe (scDefaultCost sc) id (spendCost opts)

  mgr <- newManager tlsManagerSettings
  baseUrl <- parseBaseUrl (scServerUrl sc)
  let env = mkClientEnv mgr baseUrl

  params <- newParams (scParamsOrg sc) (scParamsSvc sc) (scParamsDep sc) (scParamsVer sc)

#ifdef ACT_L16
  -- Create spend proof
  (proof, preRef) <- proveSpend @L16 token params (scalarFromWord64 cost)
  let SpendProof proofBytes = proof

  -- Build Token wire format
  let challengeBytes = encodeTokenChallenge
        (scIssuerName sc)
        BS.empty
        (scOriginInfo sc)
        (scCredentialContext sc)
      challengeDigest = hash challengeBytes
      keyId = issuerKeyId pk
      tokenWireBytes = encodeToken challengeDigest keyId proofBytes

  -- Send to server
  refundBytes <- redeemToken env tokenWireBytes

  -- Construct new credential from refund
  newTokenResult <- refundToCreditToken @L16 preRef params proof (Refund refundBytes) pk
  case newTokenResult of
    Right newToken -> do
      let newCredits = creditTokenCredits newToken
          CreditToken newTokenBytes = newToken
      case scalarToWord64 newCredits of
        Just c -> do
          saveCredential conn newTokenBytes c
          putStrLn $ "Spent " ++ show cost ++ " credits. Remaining: " ++ show c
        Nothing -> do
          saveCredential conn newTokenBytes 0
          putStrLn $ "Spent " ++ show cost ++ " credits."
    Left err -> fail $ "Failed to process refund: " ++ show err
#else
  fail "act-client requires ACT_L16"
#endif

runStatus :: FilePath -> IO ()
runStatus dbPath = do
  conn <- open dbPath
  initClientDB conn

  mConfig <- loadServerConfig conn
  case mConfig of
    Nothing -> putStrLn "Not initialized. Run 'init' first."
    Just sc -> do
      putStrLn $ "Server: " ++ scServerUrl sc
      putStrLn $ "Initial credits: " ++ show (scInitialCredits sc)
      putStrLn $ "Default cost: " ++ show (scDefaultCost sc)

      mCred <- loadActiveCredential conn
      case mCred of
        Nothing -> putStrLn "No active credential."
        Just (_, credits) ->
          putStrLn $ "Active credential balance: " ++ show credits

decodeHex :: BS.ByteString -> BS.ByteString
decodeHex bs = case B16.decode bs of
  Right decoded -> decoded
  Left _        -> BS.empty
