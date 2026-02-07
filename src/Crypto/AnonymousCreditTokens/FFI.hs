{-# LANGUAGE ForeignFunctionInterface #-}
module Crypto.AnonymousCreditTokens.FFI where

import Foreign.C.String (CString)
import Foreign.C.Types (CInt(..), CSize(..))
import Foreign.Ptr (Ptr, FunPtr)
import Data.Word (Word8)
import Crypto.AnonymousCreditTokens.Types (ACTParams)

-- ---------------------------------------------------------------------------
-- Shared (L-independent) imports
-- ---------------------------------------------------------------------------

-- Params (opaque pointer)
foreign import ccall unsafe "act_params_new"
  c_act_params_new :: CString -> CString -> CString -> CString -> IO (Ptr ACTParams)

foreign import ccall unsafe "&act_params_free"
  c_act_params_free :: FunPtr (Ptr ACTParams -> IO ())

-- Buffer management
foreign import ccall unsafe "act_free_buffer"
  c_act_free_buffer :: Ptr Word8 -> CSize -> IO ()

-- PrivateKey
foreign import ccall unsafe "act_private_key_random"
  c_act_private_key_random :: Ptr (Ptr Word8) -> Ptr CSize -> IO CInt

foreign import ccall unsafe "act_private_key_public"
  c_act_private_key_public :: Ptr Word8 -> CSize -> Ptr (Ptr Word8) -> Ptr CSize -> IO CInt

-- PreIssuance
foreign import ccall unsafe "act_pre_issuance_random"
  c_act_pre_issuance_random :: Ptr (Ptr Word8) -> Ptr CSize -> IO CInt

foreign import ccall unsafe "act_pre_issuance_request"
  c_act_pre_issuance_request :: Ptr Word8 -> CSize -> Ptr ACTParams -> Ptr (Ptr Word8) -> Ptr CSize -> IO CInt

-- to_credit_token (L-independent)
foreign import ccall unsafe "act_to_credit_token"
  c_act_to_credit_token :: Ptr Word8 -> CSize -> Ptr ACTParams
                        -> Ptr Word8 -> CSize
                        -> Ptr Word8 -> CSize
                        -> Ptr Word8 -> CSize
                        -> Ptr (Ptr Word8) -> Ptr CSize -> IO CInt

-- CreditToken accessors (L-independent)
foreign import ccall unsafe "act_credit_token_nullifier"
  c_act_credit_token_nullifier :: Ptr Word8 -> CSize -> Ptr Word8 -> IO CInt

foreign import ccall unsafe "act_credit_token_credits"
  c_act_credit_token_credits :: Ptr Word8 -> CSize -> Ptr Word8 -> IO CInt

-- ---------------------------------------------------------------------------
-- L=8
-- ---------------------------------------------------------------------------

foreign import ccall unsafe "act_issue_8"
  c_act_issue_8 :: Ptr Word8 -> CSize -> Ptr ACTParams
                -> Ptr Word8 -> CSize
                -> Ptr Word8 -> Ptr Word8
                -> Ptr (Ptr Word8) -> Ptr CSize -> IO CInt

foreign import ccall unsafe "act_prove_spend_8"
  c_act_prove_spend_8 :: Ptr Word8 -> CSize -> Ptr ACTParams
                      -> Ptr Word8
                      -> Ptr (Ptr Word8) -> Ptr CSize
                      -> Ptr (Ptr Word8) -> Ptr CSize -> IO CInt

foreign import ccall unsafe "act_refund_8"
  c_act_refund_8 :: Ptr Word8 -> CSize -> Ptr ACTParams
                 -> Ptr Word8 -> CSize
                 -> Ptr (Ptr Word8) -> Ptr CSize -> IO CInt

foreign import ccall unsafe "act_refund_to_credit_token_8"
  c_act_refund_to_credit_token_8 :: Ptr Word8 -> CSize -> Ptr ACTParams
                                 -> Ptr Word8 -> CSize
                                 -> Ptr Word8 -> CSize
                                 -> Ptr Word8 -> CSize
                                 -> Ptr (Ptr Word8) -> Ptr CSize -> IO CInt

foreign import ccall unsafe "act_spend_proof_nullifier_8"
  c_act_spend_proof_nullifier_8 :: Ptr Word8 -> CSize -> Ptr Word8 -> IO CInt

foreign import ccall unsafe "act_spend_proof_charge_8"
  c_act_spend_proof_charge_8 :: Ptr Word8 -> CSize -> Ptr Word8 -> IO CInt

foreign import ccall unsafe "act_spend_proof_context_8"
  c_act_spend_proof_context_8 :: Ptr Word8 -> CSize -> Ptr Word8 -> IO CInt

-- ---------------------------------------------------------------------------
-- L=16
-- ---------------------------------------------------------------------------

foreign import ccall unsafe "act_issue_16"
  c_act_issue_16 :: Ptr Word8 -> CSize -> Ptr ACTParams
                 -> Ptr Word8 -> CSize
                 -> Ptr Word8 -> Ptr Word8
                 -> Ptr (Ptr Word8) -> Ptr CSize -> IO CInt

foreign import ccall unsafe "act_prove_spend_16"
  c_act_prove_spend_16 :: Ptr Word8 -> CSize -> Ptr ACTParams
                       -> Ptr Word8
                       -> Ptr (Ptr Word8) -> Ptr CSize
                       -> Ptr (Ptr Word8) -> Ptr CSize -> IO CInt

foreign import ccall unsafe "act_refund_16"
  c_act_refund_16 :: Ptr Word8 -> CSize -> Ptr ACTParams
                  -> Ptr Word8 -> CSize
                  -> Ptr (Ptr Word8) -> Ptr CSize -> IO CInt

foreign import ccall unsafe "act_refund_to_credit_token_16"
  c_act_refund_to_credit_token_16 :: Ptr Word8 -> CSize -> Ptr ACTParams
                                  -> Ptr Word8 -> CSize
                                  -> Ptr Word8 -> CSize
                                  -> Ptr Word8 -> CSize
                                  -> Ptr (Ptr Word8) -> Ptr CSize -> IO CInt

foreign import ccall unsafe "act_spend_proof_nullifier_16"
  c_act_spend_proof_nullifier_16 :: Ptr Word8 -> CSize -> Ptr Word8 -> IO CInt

foreign import ccall unsafe "act_spend_proof_charge_16"
  c_act_spend_proof_charge_16 :: Ptr Word8 -> CSize -> Ptr Word8 -> IO CInt

foreign import ccall unsafe "act_spend_proof_context_16"
  c_act_spend_proof_context_16 :: Ptr Word8 -> CSize -> Ptr Word8 -> IO CInt

-- ---------------------------------------------------------------------------
-- L=32
-- ---------------------------------------------------------------------------

foreign import ccall unsafe "act_issue_32"
  c_act_issue_32 :: Ptr Word8 -> CSize -> Ptr ACTParams
                 -> Ptr Word8 -> CSize
                 -> Ptr Word8 -> Ptr Word8
                 -> Ptr (Ptr Word8) -> Ptr CSize -> IO CInt

foreign import ccall unsafe "act_prove_spend_32"
  c_act_prove_spend_32 :: Ptr Word8 -> CSize -> Ptr ACTParams
                       -> Ptr Word8
                       -> Ptr (Ptr Word8) -> Ptr CSize
                       -> Ptr (Ptr Word8) -> Ptr CSize -> IO CInt

foreign import ccall unsafe "act_refund_32"
  c_act_refund_32 :: Ptr Word8 -> CSize -> Ptr ACTParams
                  -> Ptr Word8 -> CSize
                  -> Ptr (Ptr Word8) -> Ptr CSize -> IO CInt

foreign import ccall unsafe "act_refund_to_credit_token_32"
  c_act_refund_to_credit_token_32 :: Ptr Word8 -> CSize -> Ptr ACTParams
                                  -> Ptr Word8 -> CSize
                                  -> Ptr Word8 -> CSize
                                  -> Ptr Word8 -> CSize
                                  -> Ptr (Ptr Word8) -> Ptr CSize -> IO CInt

foreign import ccall unsafe "act_spend_proof_nullifier_32"
  c_act_spend_proof_nullifier_32 :: Ptr Word8 -> CSize -> Ptr Word8 -> IO CInt

foreign import ccall unsafe "act_spend_proof_charge_32"
  c_act_spend_proof_charge_32 :: Ptr Word8 -> CSize -> Ptr Word8 -> IO CInt

foreign import ccall unsafe "act_spend_proof_context_32"
  c_act_spend_proof_context_32 :: Ptr Word8 -> CSize -> Ptr Word8 -> IO CInt

-- ---------------------------------------------------------------------------
-- L=64
-- ---------------------------------------------------------------------------

foreign import ccall unsafe "act_issue_64"
  c_act_issue_64 :: Ptr Word8 -> CSize -> Ptr ACTParams
                 -> Ptr Word8 -> CSize
                 -> Ptr Word8 -> Ptr Word8
                 -> Ptr (Ptr Word8) -> Ptr CSize -> IO CInt

foreign import ccall unsafe "act_prove_spend_64"
  c_act_prove_spend_64 :: Ptr Word8 -> CSize -> Ptr ACTParams
                       -> Ptr Word8
                       -> Ptr (Ptr Word8) -> Ptr CSize
                       -> Ptr (Ptr Word8) -> Ptr CSize -> IO CInt

foreign import ccall unsafe "act_refund_64"
  c_act_refund_64 :: Ptr Word8 -> CSize -> Ptr ACTParams
                  -> Ptr Word8 -> CSize
                  -> Ptr (Ptr Word8) -> Ptr CSize -> IO CInt

foreign import ccall unsafe "act_refund_to_credit_token_64"
  c_act_refund_to_credit_token_64 :: Ptr Word8 -> CSize -> Ptr ACTParams
                                  -> Ptr Word8 -> CSize
                                  -> Ptr Word8 -> CSize
                                  -> Ptr Word8 -> CSize
                                  -> Ptr (Ptr Word8) -> Ptr CSize -> IO CInt

foreign import ccall unsafe "act_spend_proof_nullifier_64"
  c_act_spend_proof_nullifier_64 :: Ptr Word8 -> CSize -> Ptr Word8 -> IO CInt

foreign import ccall unsafe "act_spend_proof_charge_64"
  c_act_spend_proof_charge_64 :: Ptr Word8 -> CSize -> Ptr Word8 -> IO CInt

foreign import ccall unsafe "act_spend_proof_context_64"
  c_act_spend_proof_context_64 :: Ptr Word8 -> CSize -> Ptr Word8 -> IO CInt

-- ---------------------------------------------------------------------------
-- L=128
-- ---------------------------------------------------------------------------

foreign import ccall unsafe "act_issue_128"
  c_act_issue_128 :: Ptr Word8 -> CSize -> Ptr ACTParams
                  -> Ptr Word8 -> CSize
                  -> Ptr Word8 -> Ptr Word8
                  -> Ptr (Ptr Word8) -> Ptr CSize -> IO CInt

foreign import ccall unsafe "act_prove_spend_128"
  c_act_prove_spend_128 :: Ptr Word8 -> CSize -> Ptr ACTParams
                        -> Ptr Word8
                        -> Ptr (Ptr Word8) -> Ptr CSize
                        -> Ptr (Ptr Word8) -> Ptr CSize -> IO CInt

foreign import ccall unsafe "act_refund_128"
  c_act_refund_128 :: Ptr Word8 -> CSize -> Ptr ACTParams
                   -> Ptr Word8 -> CSize
                   -> Ptr (Ptr Word8) -> Ptr CSize -> IO CInt

foreign import ccall unsafe "act_refund_to_credit_token_128"
  c_act_refund_to_credit_token_128 :: Ptr Word8 -> CSize -> Ptr ACTParams
                                   -> Ptr Word8 -> CSize
                                   -> Ptr Word8 -> CSize
                                   -> Ptr Word8 -> CSize
                                   -> Ptr (Ptr Word8) -> Ptr CSize -> IO CInt

foreign import ccall unsafe "act_spend_proof_nullifier_128"
  c_act_spend_proof_nullifier_128 :: Ptr Word8 -> CSize -> Ptr Word8 -> IO CInt

foreign import ccall unsafe "act_spend_proof_charge_128"
  c_act_spend_proof_charge_128 :: Ptr Word8 -> CSize -> Ptr Word8 -> IO CInt

foreign import ccall unsafe "act_spend_proof_context_128"
  c_act_spend_proof_context_128 :: Ptr Word8 -> CSize -> Ptr Word8 -> IO CInt
