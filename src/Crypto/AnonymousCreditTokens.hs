{-# LANGUAGE CPP #-}
-- | Haskell bindings to the Anonymous Credit Tokens library.
--
-- Use 'TypeApplications' to select the range-proof size:
--
-- @
-- {-\# LANGUAGE TypeApplications \#-}
--
-- -- Setup
-- params <- 'newParams' "org" "svc" "dep" "v1"
-- sk     <- 'generatePrivateKey'
-- let pk = 'publicKey' sk
--
-- -- Issuance (L=8)
-- pre <- 'generatePreIssuance'
-- req <- 'issuanceRequest' pre params
-- Right resp  <- 'issue' \@'L8' sk params req ('scalarFromWord64' 100) 'scalarZero'
-- Right token <- 'toCreditToken' pre params pk req resp
--
-- -- Spending
-- (proof, preRef) <- 'proveSpend' \@'L8' token params ('scalarFromWord64' 30)
-- Right ref       <- 'refund' sk params proof
-- Right newToken  <- 'refundToCreditToken' preRef params proof ref pk
-- @
module Crypto.AnonymousCreditTokens
  ( -- * Range-proof size tags
    L8, L16, L32, L64, L128
    -- * Type class
  , KnownL(..)
    -- * Types
  , Params
  , PrivateKey(..)
  , PublicKey(..)
  , PreIssuance(..)
  , IssuanceRequest(..)
  , IssuanceResponse(..)
  , CreditToken(..)
  , SpendProof(..)
  , PreRefund(..)
  , Refund(..)
  , Scalar(..)
  , ErrorCode(..)
    -- * Scalar helpers
  , scalarFromWord64
  , scalarToWord64
  , scalarZero
    -- * Setup
  , newParams
  , generatePrivateKey
  , publicKey
    -- * Issuance (client)
  , generatePreIssuance
  , issuanceRequest
    -- * Issuance (client completion, L-independent)
  , toCreditToken
    -- * CreditToken accessors (L-independent)
  , creditTokenNullifier
  , creditTokenCredits
  ) where

import Crypto.AnonymousCreditTokens.Types
import Crypto.AnonymousCreditTokens.Internal
import qualified Crypto.AnonymousCreditTokens.FFI as FFI

import Foreign.C.String (withCString)
import Foreign.ForeignPtr (newForeignPtr, withForeignPtr)
import Foreign.Ptr (nullPtr)
import System.IO.Unsafe (unsafePerformIO)

-- ---------------------------------------------------------------------------
-- KnownL class
-- ---------------------------------------------------------------------------

-- | Type class for range-proof sizes. Each instance dispatches to the
-- corresponding L-specific FFI functions.
--
-- Use @TypeApplications@ to select @l@, e.g. @'issue' \@'L8'@.
class KnownL l where
  -- | Issue credits with the given range-proof size.
  issue :: PrivateKey -> Params -> IssuanceRequest -> Scalar -> Scalar
        -> IO (Either ErrorCode (IssuanceResponse l))

  -- | Create a spend proof and pre-refund state.
  proveSpend :: CreditToken -> Params -> Scalar
             -> IO (SpendProof l, PreRefund l)

  -- | Verify a spend proof and create a refund.
  refund :: PrivateKey -> Params -> SpendProof l
         -> IO (Either ErrorCode Refund)

  -- | Convert a pre-refund + refund response into a new credit token.
  refundToCreditToken :: PreRefund l -> Params -> SpendProof l
                      -> Refund -> PublicKey
                      -> IO (Either ErrorCode CreditToken)

  -- | Get the nullifier from a spend proof.
  spendProofNullifier :: SpendProof l -> Scalar

  -- | Get the charge (spend amount) from a spend proof.
  spendProofCharge :: SpendProof l -> Scalar

  -- | Get the context from a spend proof.
  spendProofContext :: SpendProof l -> Scalar

-- ---------------------------------------------------------------------------
-- KnownL instances
-- ---------------------------------------------------------------------------

#ifdef ACT_L8
instance KnownL L8 where
  issue               = issueWith FFI.c_act_issue_8
  proveSpend          = proveSpendWith FFI.c_act_prove_spend_8
  refund              = refundWith FFI.c_act_refund_8
  refundToCreditToken = refundToCreditTokenWith FFI.c_act_refund_to_credit_token_8
  spendProofNullifier = spendProofAccessorWith FFI.c_act_spend_proof_nullifier_8
  spendProofCharge    = spendProofAccessorWith FFI.c_act_spend_proof_charge_8
  spendProofContext   = spendProofAccessorWith FFI.c_act_spend_proof_context_8
#endif

#ifdef ACT_L16
instance KnownL L16 where
  issue               = issueWith FFI.c_act_issue_16
  proveSpend          = proveSpendWith FFI.c_act_prove_spend_16
  refund              = refundWith FFI.c_act_refund_16
  refundToCreditToken = refundToCreditTokenWith FFI.c_act_refund_to_credit_token_16
  spendProofNullifier = spendProofAccessorWith FFI.c_act_spend_proof_nullifier_16
  spendProofCharge    = spendProofAccessorWith FFI.c_act_spend_proof_charge_16
  spendProofContext   = spendProofAccessorWith FFI.c_act_spend_proof_context_16
#endif

#ifdef ACT_L32
instance KnownL L32 where
  issue               = issueWith FFI.c_act_issue_32
  proveSpend          = proveSpendWith FFI.c_act_prove_spend_32
  refund              = refundWith FFI.c_act_refund_32
  refundToCreditToken = refundToCreditTokenWith FFI.c_act_refund_to_credit_token_32
  spendProofNullifier = spendProofAccessorWith FFI.c_act_spend_proof_nullifier_32
  spendProofCharge    = spendProofAccessorWith FFI.c_act_spend_proof_charge_32
  spendProofContext   = spendProofAccessorWith FFI.c_act_spend_proof_context_32
#endif

#ifdef ACT_L64
instance KnownL L64 where
  issue               = issueWith FFI.c_act_issue_64
  proveSpend          = proveSpendWith FFI.c_act_prove_spend_64
  refund              = refundWith FFI.c_act_refund_64
  refundToCreditToken = refundToCreditTokenWith FFI.c_act_refund_to_credit_token_64
  spendProofNullifier = spendProofAccessorWith FFI.c_act_spend_proof_nullifier_64
  spendProofCharge    = spendProofAccessorWith FFI.c_act_spend_proof_charge_64
  spendProofContext   = spendProofAccessorWith FFI.c_act_spend_proof_context_64
#endif

#ifdef ACT_L128
instance KnownL L128 where
  issue               = issueWith FFI.c_act_issue_128
  proveSpend          = proveSpendWith FFI.c_act_prove_spend_128
  refund              = refundWith FFI.c_act_refund_128
  refundToCreditToken = refundToCreditTokenWith FFI.c_act_refund_to_credit_token_128
  spendProofNullifier = spendProofAccessorWith FFI.c_act_spend_proof_nullifier_128
  spendProofCharge    = spendProofAccessorWith FFI.c_act_spend_proof_charge_128
  spendProofContext   = spendProofAccessorWith FFI.c_act_spend_proof_context_128
#endif

-- ---------------------------------------------------------------------------
-- Setup
-- ---------------------------------------------------------------------------

-- | Create system parameters from a domain separator.
newParams :: String -> String -> String -> String -> IO Params
newParams org svc dep ver =
  withCString org $ \cOrg ->
  withCString svc $ \cSvc ->
  withCString dep $ \cDep ->
  withCString ver $ \cVer -> do
    ptr <- FFI.c_act_params_new cOrg cSvc cDep cVer
    if ptr == nullPtr
      then error "act_params_new returned null"
      else Params <$> newForeignPtr FFI.c_act_params_free ptr

-- | Generate a random issuer private key.
generatePrivateKey :: IO PrivateKey
generatePrivateKey = do
  result <- withOutBuffer
    (\pOut lOut -> FFI.c_act_private_key_random pOut lOut)
    (== 0)
  case result of
    Right bs -> return (PrivateKey bs)
    Left _   -> error "act_private_key_random failed"

-- | Extract the public key from a private key.
publicKey :: PrivateKey -> PublicKey
publicKey (PrivateKey pkBs) = unsafePerformIO $ do
  result <- withBS pkBs $ \pkPtr pkLen ->
    withOutBuffer
      (\pOut lOut -> FFI.c_act_private_key_public pkPtr pkLen pOut lOut)
      (== 0)
  case result of
    Right bs -> return (PublicKey bs)
    Left _   -> error "act_private_key_public failed"

-- ---------------------------------------------------------------------------
-- Issuance (client)
-- ---------------------------------------------------------------------------

-- | Generate random pre-issuance state.
generatePreIssuance :: IO PreIssuance
generatePreIssuance = do
  result <- withOutBuffer
    (\pOut lOut -> FFI.c_act_pre_issuance_random pOut lOut)
    (== 0)
  case result of
    Right bs -> return (PreIssuance bs)
    Left _   -> error "act_pre_issuance_random failed"

-- | Create an issuance request from pre-issuance state.
issuanceRequest :: PreIssuance -> Params -> IO IssuanceRequest
issuanceRequest (PreIssuance piBs) (Params fpParams) =
  withBS piBs $ \piPtr piLen ->
  withForeignPtr fpParams $ \paramsPtr -> do
    result <- withOutBuffer
      (\pOut lOut -> FFI.c_act_pre_issuance_request piPtr piLen paramsPtr pOut lOut)
      (== 0)
    case result of
      Right bs -> return (IssuanceRequest bs)
      Left _   -> error "act_pre_issuance_request failed"

-- ---------------------------------------------------------------------------
-- Issuance (client completion) — L-independent
-- ---------------------------------------------------------------------------

-- | Convert pre-issuance + issuer response into a credit token.
toCreditToken :: PreIssuance -> Params -> PublicKey -> IssuanceRequest
              -> IssuanceResponse l -> IO (Either ErrorCode CreditToken)
toCreditToken (PreIssuance piBs) (Params fpParams) (PublicKey pubBs)
              (IssuanceRequest reqBs) (IssuanceResponse respBs) =
  withBS piBs $ \piPtr piLen ->
  withForeignPtr fpParams $ \paramsPtr ->
  withBS pubBs $ \pubPtr pubLen ->
  withBS reqBs $ \reqPtr reqLen ->
  withBS respBs $ \respPtr respLen -> do
    result <- withOutBuffer
      (\pOut lOut -> FFI.c_act_to_credit_token piPtr piLen paramsPtr pubPtr pubLen reqPtr reqLen respPtr respLen pOut lOut)
      (== 0)
    case result of
      Right bs  -> return (Right (CreditToken bs))
      Left rc   -> return (Left (errorCodeFromInt (fromIntegral rc)))

-- ---------------------------------------------------------------------------
-- CreditToken accessors — L-independent
-- ---------------------------------------------------------------------------

-- | Get the nullifier from a credit token.
creditTokenNullifier :: CreditToken -> Scalar
creditTokenNullifier (CreditToken tokBs) = unsafePerformIO $
  withBS tokBs $ \tokPtr tokLen -> do
    (rc, s) <- readScalar $ \out -> FFI.c_act_credit_token_nullifier tokPtr tokLen out
    if rc == 0 then return s else error "act_credit_token_nullifier failed"

-- | Get the credit amount from a credit token.
creditTokenCredits :: CreditToken -> Scalar
creditTokenCredits (CreditToken tokBs) = unsafePerformIO $
  withBS tokBs $ \tokPtr tokLen -> do
    (rc, s) <- readScalar $ \out -> FFI.c_act_credit_token_credits tokPtr tokLen out
    if rc == 0 then return s else error "act_credit_token_credits failed"
