module ACT.Crypto
  ( issuerKeyId
  , truncatedKeyId
  , computeRequestContext
  ) where

import Crypto.AnonymousCreditTokens.Types (PublicKey(..), Scalar(..))

import Crypto.Hash.SHA256 (hash)
import Data.Bits ((.&.))
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Word (Word8)

-- | Compute the full issuer key ID: SHA-256(pk_cbor).
issuerKeyId :: PublicKey -> ByteString
issuerKeyId (PublicKey pkBytes) = hash pkBytes

-- | Compute the truncated key ID: last byte of issuerKeyId.
truncatedKeyId :: PublicKey -> Word8
truncatedKeyId pk = BS.last (issuerKeyId pk)

-- | Compute the request_context scalar.
--
-- Per spec: request_context = concat(issuer_name, origin_info, credential_context, issuer_key_id)
-- Then SHA-256 the concatenation and clamp the top 4 bits of byte 31 to zero
-- (ensures value < 2^252 < group order).
computeRequestContext
  :: ByteString  -- ^ issuer_name
  -> ByteString  -- ^ origin_info
  -> ByteString  -- ^ credential_context
  -> ByteString  -- ^ issuer_key_id (32 bytes)
  -> Scalar
computeRequestContext issuerName originInfo credCtx keyId =
  let input = BS.concat [issuerName, originInfo, credCtx, keyId]
      h = hash input
      -- Clamp top 4 bits of byte 31 to zero so the value is < 2^252
      clamped = BS.init h `BS.snoc` (BS.last h .&. 0x0F)
  in Scalar clamped
