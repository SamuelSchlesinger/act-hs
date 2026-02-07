{-# LANGUAGE CPP #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE AllowAmbiguousTypes #-}
module Main (main) where

import Crypto.AnonymousCreditTokens
import Data.Word (Word64)
import qualified Data.ByteString as BS
import System.Exit (exitFailure, exitSuccess)

main :: IO ()
main = do
  -- Scalar utility tests
  testScalarUtilities

  -- Roundtrip tests for each L variant
#ifdef ACT_L8
  testRoundtrip @L8 "L=8" 100 30
  testSpendAll @L8 "L=8" 200
  testMultipleSpends @L8 "L=8" 200 [50, 30, 20]
#endif
#ifdef ACT_L16
  testRoundtrip @L16 "L=16" 1000 300
  testSpendAll @L16 "L=16" 500
  testMultipleSpends @L16 "L=16" 1000 [100, 200, 300]
#endif
#ifdef ACT_L32
  testRoundtrip @L32 "L=32" 100 30
  testSpendAll @L32 "L=32" 100
  testMultipleSpends @L32 "L=32" 500 [100, 150, 50]
#endif
#ifdef ACT_L64
  testRoundtrip @L64 "L=64" 100 30
  testSpendAll @L64 "L=64" 100
#endif
#ifdef ACT_L128
  testRoundtrip @L128 "L=128" 100 30
  testSpendAll @L128 "L=128" 100
#endif

  -- Key pair tests
  testKeyPairDeterminism

  -- Params tests
  testParamsCreation

  putStrLn ""
  putStrLn "=== All tests passed ==="
  exitSuccess

-- ---------------------------------------------------------------------------
-- Scalar utility tests
-- ---------------------------------------------------------------------------

testScalarUtilities :: IO ()
testScalarUtilities = do
  putStrLn "=== Scalar utility tests ==="

  -- scalarZero
  assertEq "scalarZero length" (let Scalar bs = scalarZero in BS.length bs) 32
  assertEq "scalarZero bytes" (let Scalar bs = scalarZero in BS.all (== 0) bs) True
  assertEq "scalarZero toWord64" (scalarToWord64 scalarZero) (Just 0)
  putStrLn "  OK: scalarZero"

  -- scalarFromWord64 roundtrip
  assertEq "fromWord64 0" (scalarToWord64 (scalarFromWord64 0)) (Just 0)
  assertEq "fromWord64 1" (scalarToWord64 (scalarFromWord64 1)) (Just 1)
  assertEq "fromWord64 255" (scalarToWord64 (scalarFromWord64 255)) (Just 255)
  assertEq "fromWord64 256" (scalarToWord64 (scalarFromWord64 256)) (Just 256)
  assertEq "fromWord64 65535" (scalarToWord64 (scalarFromWord64 65535)) (Just 65535)
  assertEq "fromWord64 maxBound" (scalarToWord64 (scalarFromWord64 maxBound)) (Just (maxBound :: Word64))
  putStrLn "  OK: scalarFromWord64/scalarToWord64 roundtrip"

  -- scalarFromWord64 length
  assertEq "fromWord64 length" (let Scalar bs = scalarFromWord64 42 in BS.length bs) 32
  putStrLn "  OK: scalarFromWord64 produces 32-byte scalar"

  -- scalarToWord64 rejects oversized values
  let bigScalar = Scalar (BS.replicate 8 0xFF <> BS.pack [1] <> BS.replicate 23 0)
  assertEq "toWord64 overflow" (scalarToWord64 bigScalar) Nothing
  putStrLn "  OK: scalarToWord64 rejects overflow"

  -- scalarToWord64 rejects wrong-length
  let shortScalar = Scalar (BS.replicate 16 0)
  assertEq "toWord64 short" (scalarToWord64 shortScalar) Nothing
  putStrLn "  OK: scalarToWord64 rejects wrong length"

  -- Scalar equality
  assertEq "scalar eq same" (scalarFromWord64 42 == scalarFromWord64 42) True
  assertEq "scalar eq diff" (scalarFromWord64 42 == scalarFromWord64 43) False
  assertEq "scalar zero eq" (scalarZero == scalarFromWord64 0) True
  putStrLn "  OK: Scalar Eq instance"

  putStrLn "  Scalar utility tests PASSED"

-- ---------------------------------------------------------------------------
-- Roundtrip tests
-- ---------------------------------------------------------------------------

testRoundtrip :: forall l. KnownL l => String -> Word64 -> Word64 -> IO ()
testRoundtrip label totalCredits spendCredits = do
  let remainingCredits = totalCredits - spendCredits
  putStrLn $ "=== " ++ label ++ " roundtrip ==="

  -- Setup
  params <- newParams "test-org" "test-service" "test" "2024-01-01"
  sk <- generatePrivateKey
  let pk = publicKey sk

  -- Issue
  putStrLn $ "  Issuing " ++ show totalCredits ++ " credits..."
  preIss <- generatePreIssuance
  req <- issuanceRequest preIss params
  issueResult <- issue @l sk params req (scalarFromWord64 totalCredits) scalarZero
  resp <- case issueResult of
    Right r  -> return r
    Left err -> do putStrLn $ "  FAIL: issue returned " ++ show err; exitFailure

  tokenResult <- toCreditToken preIss params pk req resp
  token <- case tokenResult of
    Right t  -> return t
    Left err -> do putStrLn $ "  FAIL: toCreditToken returned " ++ show err; exitFailure

  assertEq "token credits" (creditTokenCredits token) (scalarFromWord64 totalCredits)
  putStrLn $ "  OK: token has " ++ show totalCredits ++ " credits"

  -- Spend
  putStrLn $ "  Spending " ++ show spendCredits ++ " credits..."
  (proof, preRef) <- proveSpend @l token params (scalarFromWord64 spendCredits)
  assertEq "spend charge" (spendProofCharge proof) (scalarFromWord64 spendCredits)
  putStrLn $ "  OK: spend proof charge = " ++ show spendCredits

  -- Verify nullifier on spend proof matches token
  assertEq "proof nullifier matches token"
    (spendProofNullifier proof) (creditTokenNullifier token)
  putStrLn "  OK: spend proof nullifier matches token nullifier"

  -- Refund
  putStrLn "  Processing refund..."
  refundResult <- refund sk params proof
  ref <- case refundResult of
    Right r  -> return r
    Left err -> do putStrLn $ "  FAIL: refund returned " ++ show err; exitFailure

  -- New token
  putStrLn "  Building new token from refund..."
  newTokenResult <- refundToCreditToken preRef params proof ref pk
  newToken <- case newTokenResult of
    Right t  -> return t
    Left err -> do putStrLn $ "  FAIL: refundToCreditToken returned " ++ show err; exitFailure

  assertEq "remaining credits" (creditTokenCredits newToken) (scalarFromWord64 remainingCredits)
  putStrLn $ "  OK: new token has " ++ show remainingCredits ++ " credits"

  -- Nullifier check
  let null1 = creditTokenNullifier token
      null2 = creditTokenNullifier newToken
  if null1 == null2
    then do putStrLn "  FAIL: nullifiers should differ"; exitFailure
    else putStrLn "  OK: nullifiers are distinct"
  putStrLn $ "  " ++ label ++ " PASSED"

-- ---------------------------------------------------------------------------
-- Spend all credits
-- ---------------------------------------------------------------------------

testSpendAll :: forall l. KnownL l => String -> Word64 -> IO ()
testSpendAll label totalCredits = do
  putStrLn $ "=== " ++ label ++ " spend all credits ==="

  params <- newParams "test-org" "test-service" "test" "2024-01-01"
  sk <- generatePrivateKey
  let pk = publicKey sk

  -- Issue
  preIss <- generatePreIssuance
  req <- issuanceRequest preIss params
  Right resp <- issue @l sk params req (scalarFromWord64 totalCredits) scalarZero
  Right token <- toCreditToken preIss params pk req resp

  -- Spend ALL credits
  putStrLn $ "  Spending all " ++ show totalCredits ++ " credits..."
  (proof, preRef) <- proveSpend @l token params (scalarFromWord64 totalCredits)
  assertEq "spend all charge" (spendProofCharge proof) (scalarFromWord64 totalCredits)

  -- Refund
  Right ref <- refund sk params proof
  Right newToken <- refundToCreditToken preRef params proof ref pk

  assertEq "zero credits remaining" (creditTokenCredits newToken) (scalarFromWord64 0)
  putStrLn "  OK: new token has 0 credits"
  putStrLn $ "  " ++ label ++ " spend all PASSED"

-- ---------------------------------------------------------------------------
-- Multiple sequential spends
-- ---------------------------------------------------------------------------

testMultipleSpends :: forall l. KnownL l => String -> Word64 -> [Word64] -> IO ()
testMultipleSpends label totalCredits spendAmounts = do
  putStrLn $ "=== " ++ label ++ " multiple spends ==="

  params <- newParams "test-org" "test-service" "test" "2024-01-01"
  sk <- generatePrivateKey
  let pk = publicKey sk

  -- Issue
  preIss <- generatePreIssuance
  req <- issuanceRequest preIss params
  Right resp <- issue @l sk params req (scalarFromWord64 totalCredits) scalarZero
  Right initialToken <- toCreditToken preIss params pk req resp

  -- Sequential spends
  let go _token [] remaining = do
        putStrLn $ "  OK: final balance = " ++ show remaining
        putStrLn $ "  " ++ label ++ " multiple spends PASSED"
      go token (amount:rest) remaining = do
        putStrLn $ "  Spending " ++ show amount ++ " (balance: " ++ show remaining ++ ")..."
        (proof, preRef) <- proveSpend @l token params (scalarFromWord64 amount)
        Right ref <- refund sk params proof
        Right newToken <- refundToCreditToken preRef params proof ref pk
        let remaining' = remaining - amount
        assertEq ("credits after spend " ++ show amount)
          (creditTokenCredits newToken) (scalarFromWord64 remaining')
        go newToken rest remaining'

  go initialToken spendAmounts totalCredits

-- ---------------------------------------------------------------------------
-- Key pair determinism
-- ---------------------------------------------------------------------------

testKeyPairDeterminism :: IO ()
testKeyPairDeterminism = do
  putStrLn "=== Key pair tests ==="

  -- Each generatePrivateKey call produces a unique key
  sk1 <- generatePrivateKey
  sk2 <- generatePrivateKey
  let PrivateKey bs1 = sk1
      PrivateKey bs2 = sk2
  if bs1 == bs2
    then do putStrLn "  FAIL: two generated keys are identical"; exitFailure
    else putStrLn "  OK: generated keys are distinct"

  -- publicKey is deterministic
  let pk1a = publicKey sk1
      pk1b = publicKey sk1
      PublicKey pkBs1a = pk1a
      PublicKey pkBs1b = pk1b
  assertEq "publicKey deterministic" pkBs1a pkBs1b
  putStrLn "  OK: publicKey is deterministic"

  -- Different private keys produce different public keys
  let PublicKey pkBs2 = publicKey sk2
  if pkBs1a == pkBs2
    then do putStrLn "  FAIL: different private keys gave same public key"; exitFailure
    else putStrLn "  OK: different private keys produce different public keys"

  putStrLn "  Key pair tests PASSED"

-- ---------------------------------------------------------------------------
-- Params creation
-- ---------------------------------------------------------------------------

testParamsCreation :: IO ()
testParamsCreation = do
  putStrLn "=== Params creation tests ==="

  -- Creating params should succeed with various inputs
  _ <- newParams "org1" "svc1" "dep1" "v1"
  putStrLn "  OK: created params with simple strings"

  _ <- newParams "" "" "" ""
  putStrLn "  OK: created params with empty strings"

  _ <- newParams "a-longer-org-name" "my-service" "production" "2024-01-01"
  putStrLn "  OK: created params with longer strings"

  putStrLn "  Params creation tests PASSED"

-- ---------------------------------------------------------------------------
-- Helpers
-- ---------------------------------------------------------------------------

assertEq :: (Eq a, Show a) => String -> a -> a -> IO ()
assertEq label actual expected
  | actual == expected = return ()
  | otherwise = do
      putStrLn $ "  FAIL: " ++ label ++ ": expected " ++ show expected ++ ", got " ++ show actual
      exitFailure
