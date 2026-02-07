{-# LANGUAGE CPP #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeApplications #-}
module Main (main) where

import ACT.Server.API (actAPI)
import ACT.Server.Crypto (issuerKeyId, truncatedKeyId, computeRequestContext)
import ACT.Server.DB (initDB, loadOrCreateKeyPair, checkAndStoreNullifier)
import ACT.Server.Handlers (server)
import ACT.Server.Types (ServerState(..), IssuerDirectory(..))
import ACT.Server.WireFormat (tokenType, parseTokenRequest, parseToken, encodeTokenChallenge)

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
  -- Unit tests (no server needed)
  testWireFormat
  testCrypto
  testDB

#ifdef ACT_L16
  -- End-to-end tests
  testEndToEnd
  testErrorCases
  putStrLn ""
  putStrLn "=== All act-server tests passed ==="
  exitSuccess
#else
  putStrLn "act-server tests require ACT_L16"
  exitFailure
#endif

-- =========================================================================
-- WireFormat unit tests
-- =========================================================================

testWireFormat :: IO ()
testWireFormat = do
  putStrLn "=== WireFormat unit tests ==="

  -- tokenType constant
  assertEq "tokenType" tokenType 0xE5AD
  putStrLn "  OK: tokenType = 0xE5AD"

  -- parseTokenRequest: valid
  let validReq = BS.concat [putWord16BE 0xE5AD, BS.singleton 0x42, "request-payload"]
  case parseTokenRequest validReq of
    Right (truncId, payload) -> do
      assertEq "truncated key id" truncId 0x42
      assertEq "request payload" payload "request-payload"
      putStrLn "  OK: parseTokenRequest valid"
    Left err -> do putStrLn $ "  FAIL: parseTokenRequest: " ++ err; exitFailure

  -- parseTokenRequest: too short
  case parseTokenRequest (BS.pack [0xE5, 0xAD]) of
    Left _ -> putStrLn "  OK: parseTokenRequest rejects too-short input"
    Right _ -> do putStrLn "  FAIL: expected too-short rejection"; exitFailure

  -- parseTokenRequest: empty
  case parseTokenRequest BS.empty of
    Left _ -> putStrLn "  OK: parseTokenRequest rejects empty input"
    Right _ -> do putStrLn "  FAIL: expected empty rejection"; exitFailure

  -- parseTokenRequest: wrong token type
  let wrongType = BS.concat [putWord16BE 0x0001, BS.singleton 0x42, "payload"]
  case parseTokenRequest wrongType of
    Left _ -> putStrLn "  OK: parseTokenRequest rejects wrong token type"
    Right _ -> do putStrLn "  FAIL: expected wrong type rejection"; exitFailure

  -- parseToken: valid
  let challengeDigest = BS.replicate 32 0xAA
      issuerKeyIdBytes = BS.replicate 32 0xBB
      spendProof = "spend-proof-data"
      validToken = BS.concat [putWord16BE 0xE5AD, challengeDigest, issuerKeyIdBytes, spendProof]
  case parseToken validToken of
    Right (cd, kid, sp) -> do
      assertEq "challenge digest" cd challengeDigest
      assertEq "issuer key id" kid issuerKeyIdBytes
      assertEq "spend proof" sp spendProof
      putStrLn "  OK: parseToken valid"
    Left err -> do putStrLn $ "  FAIL: parseToken: " ++ err; exitFailure

  -- parseToken: too short
  case parseToken (BS.replicate 65 0) of
    Left _ -> putStrLn "  OK: parseToken rejects too-short input"
    Right _ -> do putStrLn "  FAIL: expected too-short rejection"; exitFailure

  -- parseToken: wrong token type
  let wrongTypeToken = BS.concat [putWord16BE 0x0001, BS.replicate 64 0]
  case parseToken wrongTypeToken of
    Left _ -> putStrLn "  OK: parseToken rejects wrong token type"
    Right _ -> do putStrLn "  FAIL: expected wrong type rejection"; exitFailure

  -- parseToken: minimal valid (66 bytes, empty spend proof)
  let minimalToken = BS.concat [putWord16BE 0xE5AD, BS.replicate 64 0]
  case parseToken minimalToken of
    Right (_, _, sp) -> do
      assertEq "minimal token empty proof" sp BS.empty
      putStrLn "  OK: parseToken minimal valid (empty proof)"
    Left err -> do putStrLn $ "  FAIL: parseToken minimal: " ++ err; exitFailure

  -- encodeTokenChallenge: structure
  let encoded = encodeTokenChallenge "issuer" "" "origin" ""
  -- Should start with token type
  assertEq "challenge starts with token type" (BS.take 2 encoded) (putWord16BE tokenType)
  putStrLn "  OK: encodeTokenChallenge structure"

  -- encodeTokenChallenge: empty inputs
  let encodedEmpty = encodeTokenChallenge "" "" "" ""
  assertEq "challenge empty starts with token type" (BS.take 2 encodedEmpty) (putWord16BE tokenType)
  putStrLn "  OK: encodeTokenChallenge with empty inputs"

  -- encodeTokenChallenge: deterministic
  let enc1 = encodeTokenChallenge "a" "b" "c" "d"
      enc2 = encodeTokenChallenge "a" "b" "c" "d"
  assertEq "challenge deterministic" enc1 enc2
  putStrLn "  OK: encodeTokenChallenge is deterministic"

  -- encodeTokenChallenge: different inputs produce different output
  let enc3 = encodeTokenChallenge "x" "b" "c" "d"
  if enc1 == enc3
    then do putStrLn "  FAIL: different inputs should produce different challenges"; exitFailure
    else putStrLn "  OK: different inputs produce different challenges"

  putStrLn "  WireFormat unit tests PASSED"

-- =========================================================================
-- Crypto unit tests
-- =========================================================================

testCrypto :: IO ()
testCrypto = do
  putStrLn "=== Crypto unit tests ==="

  sk <- generatePrivateKey
  let pk = publicKey sk

  -- issuerKeyId: returns 32-byte SHA-256
  let kid = issuerKeyId pk
  assertEq "issuerKeyId length" (BS.length kid) 32
  putStrLn "  OK: issuerKeyId is 32 bytes"

  -- issuerKeyId: deterministic
  let kid2 = issuerKeyId pk
  assertEq "issuerKeyId deterministic" kid kid2
  putStrLn "  OK: issuerKeyId is deterministic"

  -- issuerKeyId: equals SHA-256(pk_bytes)
  let PublicKey pkBytes = pk
      expected = hash pkBytes
  assertEq "issuerKeyId = SHA-256(pk)" kid expected
  putStrLn "  OK: issuerKeyId = SHA-256(pk_bytes)"

  -- issuerKeyId: different keys produce different IDs
  sk2 <- generatePrivateKey
  let pk2 = publicKey sk2
      kid3 = issuerKeyId pk2
  if kid == kid3
    then do putStrLn "  FAIL: different keys should have different IDs"; exitFailure
    else putStrLn "  OK: different keys produce different issuerKeyIds"

  -- truncatedKeyId: last byte of issuerKeyId
  let truncId = truncatedKeyId pk
  assertEq "truncatedKeyId" truncId (BS.last kid)
  putStrLn "  OK: truncatedKeyId = last byte of issuerKeyId"

  -- computeRequestContext: produces 32-byte scalar
  let Scalar ctxBytes = computeRequestContext "issuer" "origin" "" kid
  assertEq "context length" (BS.length ctxBytes) 32
  putStrLn "  OK: computeRequestContext produces 32-byte scalar"

  -- computeRequestContext: deterministic
  let ctx1 = computeRequestContext "issuer" "origin" "" kid
      ctx2 = computeRequestContext "issuer" "origin" "" kid
  assertEq "context deterministic" ctx1 ctx2
  putStrLn "  OK: computeRequestContext is deterministic"

  -- computeRequestContext: top 4 bits of last byte are zero (clamping)
  let Scalar ctxBs = computeRequestContext "test" "test" "test" kid
  assertEq "context clamped" (BS.last ctxBs .&. 0xF0) 0
  putStrLn "  OK: computeRequestContext clamps top 4 bits"

  -- computeRequestContext: different inputs produce different contexts
  let ctx3 = computeRequestContext "different" "origin" "" kid
  if ctx1 == ctx3
    then do putStrLn "  FAIL: different inputs should produce different contexts"; exitFailure
    else putStrLn "  OK: different inputs produce different contexts"

  putStrLn "  Crypto unit tests PASSED"

-- =========================================================================
-- DB unit tests
-- =========================================================================

testDB :: IO ()
testDB = do
  putStrLn "=== DB unit tests ==="

  -- initDB and loadOrCreateKeyPair: fresh DB
  conn <- open ":memory:"
  initDB conn
  (sk1, pk1) <- loadOrCreateKeyPair conn
  let PrivateKey skBs1 = sk1
      PublicKey pkBs1 = pk1
  assertEq "sk not empty" (BS.length skBs1 > 0) True
  assertEq "pk not empty" (BS.length pkBs1 > 0) True
  putStrLn "  OK: loadOrCreateKeyPair generates keys on fresh DB"

  -- loadOrCreateKeyPair: returns same keys on second call
  (sk2, pk2) <- loadOrCreateKeyPair conn
  let PrivateKey skBs2 = sk2
      PublicKey pkBs2 = pk2
  assertEq "sk persisted" skBs1 skBs2
  assertEq "pk persisted" pkBs1 pkBs2
  putStrLn "  OK: loadOrCreateKeyPair returns persisted keys"

  -- checkAndStoreNullifier: new nullifier returns True
  let nullifier1 = BS.replicate 32 0x01
  isNew1 <- checkAndStoreNullifier conn nullifier1
  assertEq "new nullifier" isNew1 True
  putStrLn "  OK: new nullifier returns True"

  -- checkAndStoreNullifier: duplicate returns False
  isNew2 <- checkAndStoreNullifier conn nullifier1
  assertEq "duplicate nullifier" isNew2 False
  putStrLn "  OK: duplicate nullifier returns False"

  -- checkAndStoreNullifier: different nullifier returns True
  let nullifier2 = BS.replicate 32 0x02
  isNew3 <- checkAndStoreNullifier conn nullifier2
  assertEq "different nullifier" isNew3 True
  putStrLn "  OK: different nullifier returns True"

  -- checkAndStoreNullifier: second duplicate still False
  isNew4 <- checkAndStoreNullifier conn nullifier1
  assertEq "triple nullifier" isNew4 False
  putStrLn "  OK: repeated duplicate still returns False"

  -- initDB is idempotent (can be called twice)
  initDB conn
  (sk3, _) <- loadOrCreateKeyPair conn
  let PrivateKey skBs3 = sk3
  assertEq "keys survive re-init" skBs1 skBs3
  putStrLn "  OK: initDB is idempotent"

  putStrLn "  DB unit tests PASSED"

-- =========================================================================
-- End-to-end tests
-- =========================================================================

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

-- =========================================================================
-- Error case tests
-- =========================================================================

testErrorCases :: IO ()
testErrorCases = do
  putStrLn "=== Error case tests ==="

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
    -- Error 1: Token request with wrong token type
    -- ---------------------------------------------------------------
    putStrLn "  [E1] Token request with wrong token type..."
    let wrongTypeReq = BS.concat [putWord16BE 0x0001, BS.singleton 0x42, "payload"]
    result1 <- runClientM (tokenRequestClient (LBS.fromStrict wrongTypeReq)) env
    case result1 of
      Left (FailureResponse _ resp)
        | statusCode (responseStatusCode resp) == 422 ->
            putStrLn "  OK: wrong token type rejected with 422"
      Left err -> do putStrLn $ "  FAIL: expected 422, got: " ++ show err; exitFailure
      Right _  -> do putStrLn "  FAIL: expected 422, got success"; exitFailure

    -- ---------------------------------------------------------------
    -- Error 2: Token request with wrong truncated key ID
    -- ---------------------------------------------------------------
    putStrLn "  [E2] Token request with wrong truncated key ID..."
    let wrongTruncId = truncatedKeyId pk + 1  -- intentionally wrong
    preIss <- generatePreIssuance
    req <- issuanceRequest preIss params
    let IssuanceRequest reqBytes = req
        wrongKeyReq = BS.concat
          [ putWord16BE tokenType
          , BS.singleton wrongTruncId
          , reqBytes
          ]
    result2 <- runClientM (tokenRequestClient (LBS.fromStrict wrongKeyReq)) env
    case result2 of
      Left (FailureResponse _ resp)
        | statusCode (responseStatusCode resp) == 422 ->
            putStrLn "  OK: wrong truncated key ID rejected with 422"
      Left err -> do putStrLn $ "  FAIL: expected 422, got: " ++ show err; exitFailure
      Right _  -> do putStrLn "  FAIL: expected 422, got success"; exitFailure

    -- ---------------------------------------------------------------
    -- Error 3: Token redeem with wrong token type
    -- ---------------------------------------------------------------
    putStrLn "  [E3] Token redeem with wrong token type..."
    let wrongTypeRedeem = BS.concat [putWord16BE 0x0001, BS.replicate 64 0, "proof"]
    result3 <- runClientM (tokenRedeemClient (LBS.fromStrict wrongTypeRedeem)) env
    case result3 of
      Left (FailureResponse _ resp)
        | statusCode (responseStatusCode resp) == 422 ->
            putStrLn "  OK: wrong token type in redeem rejected with 422"
      Left err -> do putStrLn $ "  FAIL: expected 422, got: " ++ show err; exitFailure
      Right _  -> do putStrLn "  FAIL: expected 422, got success"; exitFailure

    -- ---------------------------------------------------------------
    -- Error 4: Token redeem with wrong issuer key ID
    -- ---------------------------------------------------------------
    putStrLn "  [E4] Token redeem with wrong issuer key ID..."
    let challengeBytes = encodeTokenChallenge issuerName BS.empty originInfo credCtx
        challengeDigest = hash challengeBytes
        wrongKeyRedeem = BS.concat
          [ putWord16BE tokenType
          , challengeDigest
          , BS.replicate 32 0xFF  -- wrong key ID
          , "fake-proof"
          ]
    result4 <- runClientM (tokenRedeemClient (LBS.fromStrict wrongKeyRedeem)) env
    case result4 of
      Left (FailureResponse _ resp)
        | statusCode (responseStatusCode resp) == 422 ->
            putStrLn "  OK: wrong issuer key ID in redeem rejected with 422"
      Left err -> do putStrLn $ "  FAIL: expected 422, got: " ++ show err; exitFailure
      Right _  -> do putStrLn "  FAIL: expected 422, got success"; exitFailure

    -- ---------------------------------------------------------------
    -- Error 5: Token redeem with wrong challenge digest
    -- ---------------------------------------------------------------
    putStrLn "  [E5] Token redeem with wrong challenge digest..."
    let wrongDigestRedeem = BS.concat
          [ putWord16BE tokenType
          , BS.replicate 32 0x00  -- wrong digest
          , keyId
          , "fake-proof"
          ]
    result5 <- runClientM (tokenRedeemClient (LBS.fromStrict wrongDigestRedeem)) env
    case result5 of
      Left (FailureResponse _ resp)
        | statusCode (responseStatusCode resp) == 422 ->
            putStrLn "  OK: wrong challenge digest rejected with 422"
      Left err -> do putStrLn $ "  FAIL: expected 422, got: " ++ show err; exitFailure
      Right _  -> do putStrLn "  FAIL: expected 422, got success"; exitFailure

    -- ---------------------------------------------------------------
    -- Error 6: Token redeem too short
    -- ---------------------------------------------------------------
    putStrLn "  [E6] Token redeem with too-short body..."
    let shortRedeem = BS.pack [0xE5, 0xAD, 0x00]  -- token type + 1 byte (too short for Token)
    result6 <- runClientM (tokenRedeemClient (LBS.fromStrict shortRedeem)) env
    case result6 of
      Left (FailureResponse _ resp)
        | statusCode (responseStatusCode resp) == 422 ->
            putStrLn "  OK: too-short redeem rejected with 422"
      Left err -> do putStrLn $ "  FAIL: expected 422, got: " ++ show err; exitFailure
      Right _  -> do putStrLn "  FAIL: expected 422, got success"; exitFailure

    -- ---------------------------------------------------------------
    -- Error 7: Token request too short
    -- ---------------------------------------------------------------
    putStrLn "  [E7] Token request with too-short body..."
    let shortReq = BS.pack [0xE5]  -- just 1 byte
    result7 <- runClientM (tokenRequestClient (LBS.fromStrict shortReq)) env
    case result7 of
      Left (FailureResponse _ resp)
        | statusCode (responseStatusCode resp) == 422 ->
            putStrLn "  OK: too-short token request rejected with 422"
      Left err -> do putStrLn $ "  FAIL: expected 422, got: " ++ show err; exitFailure
      Right _  -> do putStrLn "  FAIL: expected 422, got success"; exitFailure

    putStrLn "  All error case tests PASSED"

#endif

-- =========================================================================
-- Servant client functions
-- =========================================================================

tokenRequestClient :: LBS.ByteString -> ClientM LBS.ByteString
tokenRedeemClient :: LBS.ByteString -> ClientM LBS.ByteString
issuerDirectoryClient :: ClientM IssuerDirectory
tokenRequestClient :<|> tokenRedeemClient :<|> issuerDirectoryClient = client actAPI

-- =========================================================================
-- Helpers
-- =========================================================================

-- | Encode Word16 big-endian
putWord16BE :: Word16 -> BS.ByteString
putWord16BE w = BS.pack [fromIntegral (w `shiftR` 8), fromIntegral (w .&. 0xFF)]

assertEq :: (Eq a, Show a) => String -> a -> a -> IO ()
assertEq label actual expected
  | actual == expected = return ()
  | otherwise = do
      putStrLn $ "  FAIL: " ++ label ++ ": expected " ++ show expected ++ ", got " ++ show actual
      exitFailure
