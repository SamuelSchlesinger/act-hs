module ACT.Server.WireFormat
  ( tokenType
  , parseTokenRequest
  , parseToken
  , encodeTokenResponse
  , encodeTokenChallenge
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Word (Word8, Word16)
import Data.Bits (shiftR, shiftL, (.&.))

-- | The ACT(Ristretto255) token type value.
tokenType :: Word16
tokenType = 0xE5AD

-- | Encode a Word16 as 2 big-endian bytes.
putWord16BE :: Word16 -> ByteString
putWord16BE w = BS.pack [fromIntegral (w `shiftR` 8), fromIntegral (w .&. 0xFF)]

-- | Read a Word16 from 2 big-endian bytes.
getWord16BE :: ByteString -> Word16
getWord16BE bs =
  let b0 = fromIntegral (BS.index bs 0) :: Word16
      b1 = fromIntegral (BS.index bs 1) :: Word16
  in (b0 `shiftL` 8) + b1

-- | Parse a TokenRequest from raw bytes.
-- Returns (truncated_key_id, encoded_request) or an error.
--
-- Wire format:
--   uint16_t token_type = 0xE5AD
--   uint8_t  truncated_issuer_key_id
--   uint8_t  encoded_request[...]
parseTokenRequest :: ByteString -> Either String (Word8, ByteString)
parseTokenRequest bs
  | BS.length bs < 3 = Left "TokenRequest too short"
  | tt /= tokenType  = Left $ "wrong token_type: expected " ++ show tokenType ++ ", got " ++ show tt
  | otherwise         = Right (BS.index bs 2, BS.drop 3 bs)
  where
    tt = getWord16BE bs

-- | Parse a Token from raw bytes.
-- Returns (challenge_digest, issuer_key_id, encoded_spend_proof) or an error.
--
-- Wire format:
--   uint16_t token_type = 0xE5AD
--   uint8_t  challenge_digest[32]
--   uint8_t  issuer_key_id[32]
--   uint8_t  encoded_spend_proof[...]
parseToken :: ByteString -> Either String (ByteString, ByteString, ByteString)
parseToken bs
  | BS.length bs < 66 = Left "Token too short"
  | tt /= tokenType   = Left $ "wrong token_type: expected " ++ show tokenType ++ ", got " ++ show tt
  | otherwise          = Right (challengeDigest, issuerKeyIdBytes, encodedSpendProof)
  where
    tt                = getWord16BE bs
    challengeDigest   = BS.take 32 (BS.drop 2 bs)
    issuerKeyIdBytes  = BS.take 32 (BS.drop 34 bs)
    encodedSpendProof = BS.drop 66 bs

-- | Encode a TokenResponse (just the raw CBOR IssuanceResponse bytes).
encodeTokenResponse :: ByteString -> ByteString
encodeTokenResponse = id

-- | Encode a TokenChallenge.
--
-- Wire format:
--   uint16_t token_type = 0xE5AD
--   uint16_t issuer_name_len; opaque issuer_name[issuer_name_len]
--   uint8_t  redemption_context_len; opaque redemption_context[redemption_context_len]
--   uint16_t origin_info_len; opaque origin_info[origin_info_len]
--   uint8_t  credential_context_len; opaque credential_context[credential_context_len]
encodeTokenChallenge
  :: ByteString  -- ^ issuer_name
  -> ByteString  -- ^ redemption_context (0 or 32 bytes)
  -> ByteString  -- ^ origin_info
  -> ByteString  -- ^ credential_context (0 or 32 bytes)
  -> ByteString
encodeTokenChallenge issuerName redemptionCtx originInfo credCtx = BS.concat
  [ putWord16BE tokenType
  , putWord16BE (fromIntegral (BS.length issuerName))
  , issuerName
  , BS.singleton (fromIntegral (BS.length redemptionCtx))
  , redemptionCtx
  , putWord16BE (fromIntegral (BS.length originInfo))
  , originInfo
  , BS.singleton (fromIntegral (BS.length credCtx))
  , credCtx
  ]
