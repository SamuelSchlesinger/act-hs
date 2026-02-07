-- | Types for the Anonymous Credit Tokens protocol.
--
-- All protocol messages (except 'Params') are represented as opaque
-- 'ByteString' newtypes wrapping CBOR-encoded bytes produced by the
-- Rust implementation. 'Params' is an opaque pointer to a
-- Rust-allocated struct containing precomputed basepoint tables.
--
-- Types parameterised by @l@ carry a phantom tag ('L8', 'L16', etc.)
-- indicating the range-proof bit-length used during issuance or spending.
module Crypto.AnonymousCreditTokens.Types
  ( -- * Range-proof size tags
    L8, L16, L32, L64, L128
    -- * Opaque parameters
  , ACTParams
  , Params(..)
    -- * CBOR-encoded newtypes (L-independent)
  , PrivateKey(..)
  , PublicKey(..)
  , PreIssuance(..)
  , IssuanceRequest(..)
  , Refund(..)
  , CreditToken(..)
    -- * CBOR-encoded newtypes (L-tagged)
  , IssuanceResponse(..)
  , SpendProof(..)
  , PreRefund(..)
    -- * Scalar (32-byte value)
  , Scalar(..)
  , scalarFromWord64
  , scalarToWord64
  , scalarZero
    -- * Error codes
  , ErrorCode(..)
  , errorCodeFromInt
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Word (Word64)
import Foreign.ForeignPtr (ForeignPtr)

-- | Range-proof with @L=8@  (credit values 1–255).
data L8
-- | Range-proof with @L=16@ (credit values 1–65 535).
data L16
-- | Range-proof with @L=32@ (credit values 1–2^32−1).
data L32
-- | Range-proof with @L=64@ (credit values 1–2^64−1).
data L64
-- | Range-proof with @L=128@ (credit values 1–2^128−1).
data L128

-- | Opaque C type for the Rust Params struct.
data ACTParams

-- | System parameters (opaque pointer to Rust-allocated Params).
newtype Params = Params (ForeignPtr ACTParams)

-- | Issuer private key (CBOR-encoded).
newtype PrivateKey = PrivateKey ByteString

-- | Issuer public key (CBOR-encoded).
newtype PublicKey = PublicKey ByteString

-- | Client pre-issuance state (CBOR-encoded).
newtype PreIssuance = PreIssuance ByteString

-- | Issuance request sent to issuer (CBOR-encoded).
newtype IssuanceRequest = IssuanceRequest ByteString

-- | Credit token held by client (CBOR-encoded, L-independent).
newtype CreditToken = CreditToken ByteString

-- | Issuer response to issuance request (CBOR-encoded).
-- The phantom @l@ records which range-proof size was used during issuance.
newtype IssuanceResponse l = IssuanceResponse ByteString

-- | Zero-knowledge spend proof (CBOR-encoded).
-- The phantom @l@ records which range-proof size was used.
newtype SpendProof l = SpendProof ByteString

-- | Client pre-refund state (CBOR-encoded).
-- The phantom @l@ pairs this with the 'SpendProof' from the same spend.
newtype PreRefund l = PreRefund ByteString

-- | Issuer refund response (CBOR-encoded).
newtype Refund = Refund ByteString

-- | A curve25519 scalar value (always exactly 32 bytes, little-endian).
newtype Scalar = Scalar ByteString
  deriving (Eq, Ord)

instance Show Scalar where
  show (Scalar bs) = "Scalar " ++ show (BS.unpack bs)

-- | Create a 'Scalar' from a 'Word64'. The value is encoded as a
--   32-byte little-endian integer.
scalarFromWord64 :: Word64 -> Scalar
scalarFromWord64 w = Scalar $ BS.pack bytes
  where
    bytes = [ fromIntegral (w `div` (256 ^ i) `mod` 256) | i <- [0..7 :: Int] ]
            ++ replicate 24 0

-- | Try to extract a 'Word64' from a 'Scalar'. Returns 'Nothing' if
--   the scalar value exceeds the Word64 range (i.e., bytes 8-31 are
--   not all zero).
scalarToWord64 :: Scalar -> Maybe Word64
scalarToWord64 (Scalar bs)
  | BS.length bs /= 32 = Nothing
  | BS.all (== 0) high = Just val
  | otherwise = Nothing
  where
    (low, high) = BS.splitAt 8 bs
    val = BS.foldl' (\acc b -> acc * 256 + fromIntegral b) 0 (BS.reverse low)

-- | The zero scalar.
scalarZero :: Scalar
scalarZero = Scalar (BS.replicate 32 0)

-- | Protocol error codes (matching the Rust ErrorCode repr).
data ErrorCode
  = InvalidProof       -- ^ Proof verification failed (1)
  | NullifierReuse     -- ^ Double-spend attempt detected (2)
  | MalformedRequest   -- ^ Request format is invalid (3)
  | InvalidAmount      -- ^ Credit amount out of range (4)
  | InternalError      -- ^ Unexpected internal error (-1)
  deriving (Show, Eq)

-- | Convert an FFI return code to an 'ErrorCode'.
errorCodeFromInt :: Int -> ErrorCode
errorCodeFromInt 1 = InvalidProof
errorCodeFromInt 2 = NullifierReuse
errorCodeFromInt 3 = MalformedRequest
errorCodeFromInt 4 = InvalidAmount
errorCodeFromInt _ = InternalError
