-- | Shared internal helpers used by the 'KnownL' instances.
module Crypto.AnonymousCreditTokens.Internal
  ( -- * Low-level FFI helpers
    withOutBuffer
  , withBS
  , withScalar
  , readScalar
    -- * Parameterised implementation helpers
  , issueWith
  , proveSpendWith
  , refundWith
  , refundToCreditTokenWith
  , spendProofAccessorWith
  ) where

import Crypto.AnonymousCreditTokens.Types
import qualified Crypto.AnonymousCreditTokens.FFI as FFI

import qualified Data.ByteString as BS
import qualified Data.ByteString.Unsafe as BSU
import Foreign.C.Types (CInt(..), CSize(..))
import Foreign.ForeignPtr (withForeignPtr)
import Foreign.Marshal.Alloc (alloca, allocaBytes)
import Foreign.Ptr (Ptr, castPtr)
import Foreign.Storable (peek)
import Data.Word (Word8)
import System.IO.Unsafe (unsafePerformIO)

-- ---------------------------------------------------------------------------
-- Low-level FFI helpers
-- ---------------------------------------------------------------------------

-- | Call an FFI function that writes output to (Ptr (Ptr Word8), Ptr CSize),
--   copy the result into a ByteString, and free the Rust buffer.
withOutBuffer :: (Ptr (Ptr Word8) -> Ptr CSize -> IO a) -> (a -> Bool) -> IO (Either a BS.ByteString)
withOutBuffer action isSuccess =
  alloca $ \ptrOut ->
  alloca $ \lenOut -> do
    rc <- action ptrOut lenOut
    if isSuccess rc
      then do
        ptr <- peek ptrOut
        len <- peek lenOut
        bs <- BS.packCStringLen (castPtr ptr, fromIntegral len)
        FFI.c_act_free_buffer ptr len
        return (Right bs)
      else
        return (Left rc)

-- | Use a ByteString as (Ptr Word8, CSize) pair.
withBS :: BS.ByteString -> (Ptr Word8 -> CSize -> IO a) -> IO a
withBS bs f = BSU.unsafeUseAsCStringLen bs $ \(ptr, len) ->
  f (castPtr ptr) (fromIntegral len)

-- | Use a Scalar as a Ptr Word8 (32 bytes).
withScalar :: Scalar -> (Ptr Word8 -> IO a) -> IO a
withScalar (Scalar bs) f = BSU.unsafeUseAsCString bs $ \ptr ->
  f (castPtr ptr)

-- | Read a 32-byte scalar from a caller-allocated buffer.
readScalar :: (Ptr Word8 -> IO a) -> IO (a, Scalar)
readScalar f = allocaBytes 32 $ \buf -> do
  rc <- f buf
  bs <- BS.packCStringLen (castPtr buf, 32)
  return (rc, Scalar bs)

-- ---------------------------------------------------------------------------
-- Parameterised implementation helpers
-- ---------------------------------------------------------------------------

-- | Implementation of 'issue', parameterised by the L-specific FFI function.
issueWith :: (Ptr Word8 -> CSize -> Ptr ACTParams
             -> Ptr Word8 -> CSize
             -> Ptr Word8 -> Ptr Word8
             -> Ptr (Ptr Word8) -> Ptr CSize -> IO CInt)
          -> PrivateKey -> Params -> IssuanceRequest -> Scalar -> Scalar
          -> IO (Either ErrorCode (IssuanceResponse l))
issueWith c_issue (PrivateKey pkBs) (Params fpParams) (IssuanceRequest reqBs) credits ctx =
  withBS pkBs $ \pkPtr pkLen ->
  withForeignPtr fpParams $ \paramsPtr ->
  withBS reqBs $ \reqPtr reqLen ->
  withScalar credits $ \cPtr ->
  withScalar ctx $ \ctxPtr -> do
    result <- withOutBuffer
      (\pOut lOut -> c_issue pkPtr pkLen paramsPtr reqPtr reqLen cPtr ctxPtr pOut lOut)
      (== 0)
    case result of
      Right bs  -> return (Right (IssuanceResponse bs))
      Left rc   -> return (Left (errorCodeFromInt (fromIntegral rc)))

-- | Implementation of 'proveSpend', parameterised by the L-specific FFI function.
proveSpendWith :: (Ptr Word8 -> CSize -> Ptr ACTParams
                  -> Ptr Word8
                  -> Ptr (Ptr Word8) -> Ptr CSize
                  -> Ptr (Ptr Word8) -> Ptr CSize -> IO CInt)
               -> CreditToken -> Params -> Scalar
               -> IO (SpendProof l, PreRefund l)
proveSpendWith c_prove (CreditToken tokBs) (Params fpParams) spendAmount =
  withBS tokBs $ \tokPtr tokLen ->
  withForeignPtr fpParams $ \paramsPtr ->
  withScalar spendAmount $ \sPtr ->
  alloca $ \proofPtrOut ->
  alloca $ \proofLenOut ->
  alloca $ \prPtrOut ->
  alloca $ \prLenOut -> do
    rc <- c_prove tokPtr tokLen paramsPtr sPtr
            proofPtrOut proofLenOut prPtrOut prLenOut
    if rc == 0
      then do
        proofPtr <- peek proofPtrOut
        proofLen <- peek proofLenOut
        proofBs <- BS.packCStringLen (castPtr proofPtr, fromIntegral proofLen)
        FFI.c_act_free_buffer proofPtr proofLen

        prPtr <- peek prPtrOut
        prLen <- peek prLenOut
        prBs <- BS.packCStringLen (castPtr prPtr, fromIntegral prLen)
        FFI.c_act_free_buffer prPtr prLen

        return (SpendProof proofBs, PreRefund prBs)
      else
        error $ "act_prove_spend failed with code " ++ show rc

-- | Implementation of 'refund', parameterised by the L-specific FFI function.
refundWith :: (Ptr Word8 -> CSize -> Ptr ACTParams
              -> Ptr Word8 -> CSize
              -> Ptr (Ptr Word8) -> Ptr CSize -> IO CInt)
           -> PrivateKey -> Params -> SpendProof l
           -> IO (Either ErrorCode Refund)
refundWith c_refund (PrivateKey pkBs) (Params fpParams) (SpendProof proofBs) =
  withBS pkBs $ \pkPtr pkLen ->
  withForeignPtr fpParams $ \paramsPtr ->
  withBS proofBs $ \proofPtr proofLen -> do
    result <- withOutBuffer
      (\pOut lOut -> c_refund pkPtr pkLen paramsPtr proofPtr proofLen pOut lOut)
      (== 0)
    case result of
      Right bs  -> return (Right (Refund bs))
      Left rc   -> return (Left (errorCodeFromInt (fromIntegral rc)))

-- | Implementation of 'refundToCreditToken', parameterised by the L-specific FFI function.
refundToCreditTokenWith :: (Ptr Word8 -> CSize -> Ptr ACTParams
                           -> Ptr Word8 -> CSize
                           -> Ptr Word8 -> CSize
                           -> Ptr Word8 -> CSize
                           -> Ptr (Ptr Word8) -> Ptr CSize -> IO CInt)
                        -> PreRefund l -> Params -> SpendProof l
                        -> Refund -> PublicKey
                        -> IO (Either ErrorCode CreditToken)
refundToCreditTokenWith c_reftok (PreRefund prBs) (Params fpParams) (SpendProof proofBs)
                        (Refund refBs) (PublicKey pubBs) =
  withBS prBs $ \prPtr prLen ->
  withForeignPtr fpParams $ \paramsPtr ->
  withBS proofBs $ \proofPtr proofLen ->
  withBS refBs $ \refPtr refLen ->
  withBS pubBs $ \pubPtr pubLen -> do
    result <- withOutBuffer
      (\pOut lOut -> c_reftok prPtr prLen paramsPtr proofPtr proofLen refPtr refLen pubPtr pubLen pOut lOut)
      (== 0)
    case result of
      Right bs  -> return (Right (CreditToken bs))
      Left rc   -> return (Left (errorCodeFromInt (fromIntegral rc)))

-- | Implementation of a 'SpendProof' scalar accessor, parameterised by the FFI function.
spendProofAccessorWith :: (Ptr Word8 -> CSize -> Ptr Word8 -> IO CInt)
                       -> SpendProof l -> Scalar
spendProofAccessorWith c_accessor (SpendProof proofBs) = unsafePerformIO $
  withBS proofBs $ \proofPtr proofLen -> do
    (rc, s) <- readScalar $ \out -> c_accessor proofPtr proofLen out
    if rc == 0 then return s else error "spend_proof accessor failed"
