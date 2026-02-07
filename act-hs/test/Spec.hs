{-# LANGUAGE CPP #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE AllowAmbiguousTypes #-}
module Main (main) where

import Crypto.AnonymousCreditTokens
import Data.Word (Word64)
import System.Exit (exitFailure, exitSuccess)

main :: IO ()
main = do
#ifdef ACT_L8
  testRoundtrip @L8 "L=8" 100 30
#endif
#ifdef ACT_L16
  testRoundtrip @L16 "L=16" 1000 300
#endif
#ifdef ACT_L32
  testRoundtrip @L32 "L=32" 100 30
#endif
#ifdef ACT_L64
  testRoundtrip @L64 "L=64" 100 30
#endif
#ifdef ACT_L128
  testRoundtrip @L128 "L=128" 100 30
#endif

  putStrLn ""
  putStrLn "=== All tests passed ==="
  exitSuccess

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

assertEq :: (Eq a, Show a) => String -> a -> a -> IO ()
assertEq label actual expected
  | actual == expected = return ()
  | otherwise = do
      putStrLn $ "  FAIL: " ++ label ++ ": expected " ++ show expected ++ ", got " ++ show actual
      exitFailure
