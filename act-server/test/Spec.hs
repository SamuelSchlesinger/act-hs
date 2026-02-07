{-# LANGUAGE CPP #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeApplications #-}
module Main (main) where

import ACT.Server.API (actAPI)
import ACT.Server.Crypto (issuerKeyId)
import ACT.Server.DB (initDB, loadOrCreateKeyPair)
import ACT.Server.Handlers (server)
import ACT.Server.Types (ServerState(..), IssuerDirectory(..))
import ACT.Server.WireFormat (tokenType, encodeTokenChallenge)

import Crypto.AnonymousCreditTokens
import Crypto.Hash.SHA256 (hash)

import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as LBS
import Data.Bits (shiftR, (.&.))
import Data.Word (Word16)
import Database.SQLite.Simple (open)
import Network.HTTP.Client (newManager, defaultManagerSettings)
import Network.HTTP.Types.Status (statusCode)
import qualified Network.Wai.Handler.Warp as Warp
import Servant (serve, (:<|>)(..))
import Servant.Client
import System.Exit (exitFailure, exitSuccess)

main :: IO ()
main = do
#ifdef ACT_L16
  testEndToEnd
  putStrLn ""
  putStrLn "=== All act-server tests passed ==="
  exitSuccess
#else
  putStrLn "act-server tests require ACT_L16"
  exitFailure
#endif

#ifdef ACT_L16

testEndToEnd :: IO ()
testEndToEnd = do
  putStrLn "=== End-to-End ACT Server Test ==="

  -- Build app with in-memory SQLite
  conn <- open ":memory:"
  initDB conn
  (sk, pk) <- loadOrCreateKeyPair conn

  params <- newParams "act-server" "privacy-pass" "production" "2026-01-01"

  let keyId = issuerKeyId pk
      issuerName = "test-issuer" :: BS.ByteString
      originInfo = "test-origin" :: BS.ByteString
      credCtx = BS.empty
      st = ServerState
        { ssPrivateKey       = sk
        , ssPublicKey        = pk
        , ssParams           = params
        , ssConn             = conn
        , ssIssuerName       = issuerName
        , ssOriginInfo       = originInfo
        , ssCredentialContext = credCtx
        , ssIssuerKeyId      = keyId
        , ssInitialCredits   = 1000
        }
      app = serve actAPI (server st)

  Warp.testWithApplication (return app) $ \port -> do
    mgr <- newManager defaultManagerSettings
    let env = mkClientEnv mgr (BaseUrl Http "localhost" port "")

    -- ---------------------------------------------------------------
    -- Step 1: Issuance
    -- ---------------------------------------------------------------
    putStrLn "  [1] Issuing credential with 1000 credits..."

    -- Client-side: generate pre-issuance and request
    preIss <- generatePreIssuance
    req <- issuanceRequest preIss params
    let IssuanceRequest reqBytes = req

    -- Build TokenRequest wire format
    let truncKeyId = BS.last (issuerKeyId pk)
        tokenReqBytes = BS.concat
          [ putWord16BE tokenType
          , BS.singleton truncKeyId
          , reqBytes
          ]

    -- Send issuance request
    result1 <- runClientM (tokenRequestClient (LBS.fromStrict tokenReqBytes)) env
    respBytes <- case result1 of
      Right bs -> return (LBS.toStrict bs)
      Left err -> do putStrLn $ "  FAIL: issuance request failed: " ++ show err; exitFailure

    -- Client-side: finalize credential
    tokenResult <- toCreditToken preIss params pk req (IssuanceResponse respBytes)
    token <- case tokenResult of
      Right t  -> return t
      Left err -> do putStrLn $ "  FAIL: toCreditToken returned " ++ show err; exitFailure

    -- Verify initial credits
    let credits = creditTokenCredits token
    assertEq "initial credits" credits (scalarFromWord64 1000)
    putStrLn "  OK: credential has 1000 credits"

    -- ---------------------------------------------------------------
    -- Step 2: First spend (100 credits)
    -- ---------------------------------------------------------------
    putStrLn "  [2] Spending 100 credits..."

    (proof1, preRef1) <- proveSpend @L16 token params (scalarFromWord64 100)
    let SpendProof proofBytes1 = proof1

    -- Build Token wire format
    let challengeBytes = encodeTokenChallenge issuerName BS.empty originInfo credCtx
        challengeDigest = hash challengeBytes
        tokenWireBytes1 = BS.concat
          [ putWord16BE tokenType
          , challengeDigest
          , keyId
          , proofBytes1
          ]

    -- Send redeem request
    result2 <- runClientM (tokenRedeemClient (LBS.fromStrict tokenWireBytes1)) env
    refundBytes1 <- case result2 of
      Right bs -> return (LBS.toStrict bs)
      Left err -> do putStrLn $ "  FAIL: redeem request failed: " ++ show err; exitFailure

    -- Client-side: construct new credential from refund
    let refund1 = Refund refundBytes1
    newTokenResult1 <- refundToCreditToken @L16 preRef1 params proof1 refund1 pk
    token2 <- case newTokenResult1 of
      Right t  -> return t
      Left err -> do putStrLn $ "  FAIL: refundToCreditToken returned " ++ show err; exitFailure

    let credits2 = creditTokenCredits token2
    assertEq "remaining credits after spend" credits2 (scalarFromWord64 900)
    putStrLn "  OK: new credential has 900 credits"

    -- ---------------------------------------------------------------
    -- Step 3: Double-spend (replay same Token) -> expect 409
    -- ---------------------------------------------------------------
    putStrLn "  [3] Attempting double-spend (replay)..."

    result3 <- runClientM (tokenRedeemClient (LBS.fromStrict tokenWireBytes1)) env
    case result3 of
      Left (FailureResponse _ resp)
        | statusCode (responseStatusCode resp) == 409 ->
            putStrLn "  OK: double-spend rejected with 409"
      Left err -> do putStrLn $ "  FAIL: expected 409, got: " ++ show err; exitFailure
      Right _  -> do putStrLn "  FAIL: expected 409, got success"; exitFailure

    -- ---------------------------------------------------------------
    -- Step 4: Second spend from new credential (200 credits)
    -- ---------------------------------------------------------------
    putStrLn "  [4] Spending 200 credits from new credential..."

    (proof2, preRef2) <- proveSpend @L16 token2 params (scalarFromWord64 200)
    let SpendProof proofBytes2 = proof2
        tokenWireBytes2 = BS.concat
          [ putWord16BE tokenType
          , challengeDigest
          , keyId
          , proofBytes2
          ]

    result4 <- runClientM (tokenRedeemClient (LBS.fromStrict tokenWireBytes2)) env
    refundBytes2 <- case result4 of
      Right bs -> return (LBS.toStrict bs)
      Left err -> do putStrLn $ "  FAIL: second redeem failed: " ++ show err; exitFailure

    let refund2 = Refund refundBytes2
    newTokenResult2 <- refundToCreditToken @L16 preRef2 params proof2 refund2 pk
    token3 <- case newTokenResult2 of
      Right t  -> return t
      Left err -> do putStrLn $ "  FAIL: refundToCreditToken (2) returned " ++ show err; exitFailure

    let credits3 = creditTokenCredits token3
    assertEq "remaining credits after second spend" credits3 (scalarFromWord64 700)
    putStrLn "  OK: new credential has 700 credits"

    -- ---------------------------------------------------------------
    -- Step 5: Issuer directory
    -- ---------------------------------------------------------------
    putStrLn "  [5] Fetching issuer directory..."
    result5 <- runClientM issuerDirectoryClient env
    case result5 of
      Right dir -> do
        assertEq "token_type" (idTokenType dir) tokenType
        assertEq "initial_credits" (idInitialCredits dir) 1000
        putStrLn "  OK: issuer directory returned valid data"
      Left err -> do putStrLn $ "  FAIL: issuer directory failed: " ++ show err; exitFailure

    putStrLn "  All end-to-end tests PASSED"

-- Servant client functions
tokenRequestClient :: LBS.ByteString -> ClientM LBS.ByteString
tokenRedeemClient :: LBS.ByteString -> ClientM LBS.ByteString
issuerDirectoryClient :: ClientM IssuerDirectory
tokenRequestClient :<|> tokenRedeemClient :<|> issuerDirectoryClient = client actAPI

-- Helper: encode Word16 big-endian
putWord16BE :: Word16 -> BS.ByteString
putWord16BE w = BS.pack [fromIntegral (w `shiftR` 8), fromIntegral (w .&. 0xFF)]

assertEq :: (Eq a, Show a) => String -> a -> a -> IO ()
assertEq label actual expected
  | actual == expected = return ()
  | otherwise = do
      putStrLn $ "  FAIL: " ++ label ++ ": expected " ++ show expected ++ ", got " ++ show actual
      exitFailure

#endif
