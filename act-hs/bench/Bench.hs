{-# LANGUAGE CPP #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE AllowAmbiguousTypes #-}
{-# OPTIONS_GHC -Wno-orphans #-}
module Main (main) where

import Criterion.Main
import Crypto.AnonymousCreditTokens
import Control.DeepSeq (NFData(..), rwhnf)
import Data.Word (Word64)

-- Orphan NFData instances for benchmark env support.
-- These force to WHNF which is sufficient since the underlying
-- ByteStrings are strict and fully evaluated upon construction.
instance NFData PrivateKey      where rnf = rwhnf
instance NFData PublicKey       where rnf = rwhnf
instance NFData Params          where rnf = rwhnf
instance NFData PreIssuance     where rnf = rwhnf
instance NFData IssuanceRequest where rnf = rwhnf
instance NFData CreditToken     where rnf = rwhnf
instance NFData Refund          where rnf = rwhnf
instance NFData Scalar          where rnf = rwhnf
instance NFData (IssuanceResponse l) where rnf = rwhnf
instance NFData (SpendProof l)       where rnf = rwhnf
instance NFData (PreRefund l)        where rnf = rwhnf

-- | Convenience: issue a token and return it.
issueToken :: forall l. KnownL l
           => PrivateKey -> PublicKey -> Params -> Word64
           -> IO CreditToken
issueToken sk pk params credits = do
  preIss <- generatePreIssuance
  req <- issuanceRequest preIss params
  Right resp <- issue @l sk params req (scalarFromWord64 credits) scalarZero
  Right token <- toCreditToken preIss params pk req resp
  return token

-- | Full roundtrip: issue -> spend -> refund -> reconstruct.
fullRoundtrip :: forall l. KnownL l
              => PrivateKey -> PublicKey -> Params -> Word64 -> Word64
              -> IO CreditToken
fullRoundtrip sk pk params totalCredits spendCredits = do
  token <- issueToken @l sk pk params totalCredits
  (proof, preRef) <- proveSpend @l token params (scalarFromWord64 spendCredits)
  Right ref <- refund sk params proof
  Right newToken <- refundToCreditToken preRef params proof ref pk
  return newToken

-- | Data shared across benchmarks for a given L variant.
data BenchEnv l = BenchEnv
  { envSk     :: !PrivateKey
  , envPk     :: !PublicKey
  , envParams :: !Params
  , envToken  :: !CreditToken
  , envProof  :: !(SpendProof l)
  , envPreRef :: !(PreRefund l)
  , envRefund :: !Refund
  }

instance NFData (BenchEnv l) where
  rnf (BenchEnv a b c d e f g) =
    rnf a `seq` rnf b `seq` rnf c `seq` rnf d `seq`
    rnf e `seq` rnf f `seq` rnf g

-- | Build a fixture for benchmarking a given L variant.
mkEnv :: forall l. KnownL l => Word64 -> Word64 -> IO (BenchEnv l)
mkEnv total spend = do
  sk <- generatePrivateKey
  let pk = publicKey sk
  params <- newParams "bench-org" "bench-svc" "bench" "2024-01-01"
  token <- issueToken @l sk pk params total
  (proof, preRef) <- proveSpend @l token params (scalarFromWord64 spend)
  Right ref <- refund sk params proof
  return BenchEnv
    { envSk     = sk
    , envPk     = pk
    , envParams = params
    , envToken  = token
    , envProof  = proof
    , envPreRef = preRef
    , envRefund = ref
    }

-- ---------------------------------------------------------------------------
-- Per-operation benchmark builders
-- ---------------------------------------------------------------------------

benchIssue :: forall l. KnownL l => Word64 -> Word64 -> String -> Benchmark
benchIssue total spend label =
  env (mkEnv @l total spend) $ \ ~e ->
    bench label $ nfIO $ do
      preIss <- generatePreIssuance
      req <- issuanceRequest preIss (envParams e)
      resp <- issue @l (envSk e) (envParams e) req
                (scalarFromWord64 total) scalarZero
      case resp of
        Right r  -> return r
        Left err -> error (show err)

benchProveSpend :: forall l. KnownL l => Word64 -> Word64 -> String -> Benchmark
benchProveSpend total spend label =
  env (mkEnv @l total spend) $ \ ~e ->
    bench label $ nfIO $
      proveSpend @l (envToken e) (envParams e) (scalarFromWord64 spend)

benchRefund :: forall l. KnownL l => Word64 -> Word64 -> String -> Benchmark
benchRefund total spend label =
  env (mkEnv @l total spend) $ \ ~e ->
    bench label $ nfIO $ do
      result <- refund (envSk e) (envParams e) (envProof e)
      case result of
        Right r  -> return r
        Left err -> error (show err)

benchRefundToCreditToken' :: forall l. KnownL l => Word64 -> Word64 -> String -> Benchmark
benchRefundToCreditToken' total spend label =
  env (mkEnv @l total spend) $ \ ~e ->
    bench label $ nfIO $ do
      result <- refundToCreditToken
                  (envPreRef e) (envParams e) (envProof e)
                  (envRefund e) (envPk e)
      case result of
        Right r  -> return r
        Left err -> error (show err)

benchFullRoundtrip :: forall l. KnownL l => Word64 -> Word64 -> String -> Benchmark
benchFullRoundtrip total spend label =
  env (mkEnv @l total spend) $ \ ~e ->
    bench label $ nfIO $
      fullRoundtrip @l (envSk e) (envPk e) (envParams e) total spend

-- ---------------------------------------------------------------------------
-- Main
-- ---------------------------------------------------------------------------

main :: IO ()
main = defaultMain $
  -- L-independent operations
  [ env setupIndependent $ \ ~(sk, params) ->
      bgroup "L-independent"
        [ bench "generatePrivateKey" $ nfIO generatePrivateKey
        , bench "publicKey" $ nf publicKey sk
        , bench "newParams" $ nfIO $
            newParams "bench-org" "bench-svc" "bench" "2024-01-01"
        , bench "generatePreIssuance" $ nfIO generatePreIssuance
        , bench "issuanceRequest" $ nfIO $ do
            p <- generatePreIssuance
            issuanceRequest p params
        ]
  ]
  ++
  -- Per-operation groups, each containing L variants on the x-axis.
  -- Uses concat of singletons/empties to avoid CPP comma issues.
  [ bgroup "issue" $ concat
      [
#ifdef ACT_L8
        [benchIssue @L8 100 30 "L=8"]
#else
        []
#endif
      ,
#ifdef ACT_L16
        [benchIssue @L16 1000 300 "L=16"]
#else
        []
#endif
      ,
#ifdef ACT_L32
        [benchIssue @L32 1000 300 "L=32"]
#else
        []
#endif
      ,
#ifdef ACT_L64
        [benchIssue @L64 1000 300 "L=64"]
#else
        []
#endif
      ,
#ifdef ACT_L128
        [benchIssue @L128 1000 300 "L=128"]
#else
        []
#endif
      ]

  , bgroup "proveSpend" $ concat
      [
#ifdef ACT_L8
        [benchProveSpend @L8 100 30 "L=8"]
#else
        []
#endif
      ,
#ifdef ACT_L16
        [benchProveSpend @L16 1000 300 "L=16"]
#else
        []
#endif
      ,
#ifdef ACT_L32
        [benchProveSpend @L32 1000 300 "L=32"]
#else
        []
#endif
      ,
#ifdef ACT_L64
        [benchProveSpend @L64 1000 300 "L=64"]
#else
        []
#endif
      ,
#ifdef ACT_L128
        [benchProveSpend @L128 1000 300 "L=128"]
#else
        []
#endif
      ]

  , bgroup "refund" $ concat
      [
#ifdef ACT_L8
        [benchRefund @L8 100 30 "L=8"]
#else
        []
#endif
      ,
#ifdef ACT_L16
        [benchRefund @L16 1000 300 "L=16"]
#else
        []
#endif
      ,
#ifdef ACT_L32
        [benchRefund @L32 1000 300 "L=32"]
#else
        []
#endif
      ,
#ifdef ACT_L64
        [benchRefund @L64 1000 300 "L=64"]
#else
        []
#endif
      ,
#ifdef ACT_L128
        [benchRefund @L128 1000 300 "L=128"]
#else
        []
#endif
      ]

  , bgroup "refundToCreditToken" $ concat
      [
#ifdef ACT_L8
        [benchRefundToCreditToken' @L8 100 30 "L=8"]
#else
        []
#endif
      ,
#ifdef ACT_L16
        [benchRefundToCreditToken' @L16 1000 300 "L=16"]
#else
        []
#endif
      ,
#ifdef ACT_L32
        [benchRefundToCreditToken' @L32 1000 300 "L=32"]
#else
        []
#endif
      ,
#ifdef ACT_L64
        [benchRefundToCreditToken' @L64 1000 300 "L=64"]
#else
        []
#endif
      ,
#ifdef ACT_L128
        [benchRefundToCreditToken' @L128 1000 300 "L=128"]
#else
        []
#endif
      ]

  , bgroup "full roundtrip" $ concat
      [
#ifdef ACT_L8
        [benchFullRoundtrip @L8 100 30 "L=8"]
#else
        []
#endif
      ,
#ifdef ACT_L16
        [benchFullRoundtrip @L16 1000 300 "L=16"]
#else
        []
#endif
      ,
#ifdef ACT_L32
        [benchFullRoundtrip @L32 1000 300 "L=32"]
#else
        []
#endif
      ,
#ifdef ACT_L64
        [benchFullRoundtrip @L64 1000 300 "L=64"]
#else
        []
#endif
      ,
#ifdef ACT_L128
        [benchFullRoundtrip @L128 1000 300 "L=128"]
#else
        []
#endif
      ]
  ]

  where
    setupIndependent = do
      sk <- generatePrivateKey
      params <- newParams "bench-org" "bench-svc" "bench" "2024-01-01"
      return (sk, params)
