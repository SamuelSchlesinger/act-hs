{-# LANGUAGE DataKinds #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeOperators #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}
module ACT.Server.Docs
  ( apiDocs
  , apiMarkdown
  ) where

import ACT.Server.API (ACTAPI, actAPI)
import ACT.Server.ContentTypes (PrivateCredentialRequest, PrivateCredentialResponse)
import ACT.Server.Types (IssuerDirectory(..))

import Data.Function ((&))
import Data.Proxy (Proxy(..))
import qualified Data.ByteString.Lazy as LBS
import Control.Lens ((<>~))
import Servant.API
import Servant.Docs

-- ---------------------------------------------------------------------------
-- ToSample instances
-- ---------------------------------------------------------------------------

instance ToSample LBS.ByteString where
  toSamples _ = singleSample "(raw bytes)"

instance ToSample IssuerDirectory where
  toSamples _ = singleSample IssuerDirectory
    { idTokenType        = 0xE5AD
    , idIssuerName       = "issuer.example.net"
    , idOriginInfo       = "origin.example.com"
    , idCredentialContext = ""
    , idIssuerKeyId      = "a1b2c3...(64 hex chars, SHA-256 of serialized public key)"
    , idPublicKey        = "d4e5f6...(hex-encoded CBOR serialized issuer public key)"
    , idInitialCredits   = 1000
    }

-- ---------------------------------------------------------------------------
-- Extra documentation per endpoint
-- ---------------------------------------------------------------------------

extra :: ExtraInfo ACTAPI
extra =
  extraInfo
    (Proxy :: Proxy ("token-request" :> ReqBody '[PrivateCredentialRequest] LBS.ByteString :> Post '[PrivateCredentialResponse] LBS.ByteString))
    (defAction & notes <>~
      [ DocNote "Credential Issuance (draft-schlesinger-privacypass-act, Section 7)"
        [ "Clients send a TokenRequest to obtain an Anonymous Credit Token credential."
        , ""
        , "**Wire format (TokenRequest):**"
        , ""
        , "```"
        , "uint16  token_type = 0xE5AD        (2 bytes, big-endian)"
        , "uint8   truncated_issuer_key_id    (1 byte, LSB of SHA-256(pkI))"
        , "uint8   encoded_request[Nrequest]  (CBOR IssueRequest, Section 4.1.1 of draft-schlesinger-cfrg-act)"
        , "```"
        , ""
        , "**Wire format (TokenResponse):**"
        , ""
        , "```"
        , "uint8   encoded_response[Nresponse]  (CBOR IssueResponse, Section 4.1.2 of draft-schlesinger-cfrg-act)"
        , "```"
        , ""
        , "The server validates token_type == 0xE5AD and the truncated key ID, \
          \then issues credentials with initial_credits bound to a request_context \
          \derived from issuer_name, origin_info, credential_context, and issuer_key_id."
        , ""
        , "**Errors:** HTTP 422 if the token type is wrong, the key ID doesn't match, \
          \or the encoded request is malformed."
        ]
      ])
  <>
  extraInfo
    (Proxy :: Proxy ("token-redeem" :> ReqBody '[OctetStream] LBS.ByteString :> Post '[OctetStream] LBS.ByteString))
    (defAction & notes <>~
      [ DocNote "Token Redemption (draft-schlesinger-privacypass-act, Section 8)"
        [ "Clients present a Token containing a spend proof to redeem credits. \
          \The server verifies the proof and returns a Refund that the client uses \
          \to construct a new credential with the remaining balance."
        , ""
        , "**Wire format (Token):**"
        , ""
        , "```"
        , "uint16  token_type = 0xE5AD             (2 bytes, big-endian)"
        , "uint8   challenge_digest[32]             (SHA-256 of TokenChallenge)"
        , "uint8   issuer_key_id[32]                (SHA-256 of serialized pkI)"
        , "uint8   encoded_spend_proof[Nspend_proof] (CBOR SpendProof, Section 4.1.3 of draft-schlesinger-cfrg-act)"
        , "```"
        , ""
        , "**Wire format (Refund response):**"
        , ""
        , "```"
        , "uint8   refund[Nrefund]  (CBOR Refund, Section 4.1.4 of draft-schlesinger-cfrg-act)"
        , "```"
        , ""
        , "**TokenChallenge** (used to compute challenge_digest):"
        , ""
        , "```"
        , "uint16  token_type = 0xE5AD"
        , "uint16  issuer_name_len; opaque issuer_name[issuer_name_len]"
        , "uint8   redemption_context_len; opaque redemption_context[0..32]"
        , "uint16  origin_info_len; opaque origin_info[origin_info_len]"
        , "uint8   credential_context_len; opaque credential_context[0..32]"
        , "```"
        , ""
        , "**Double-spend prevention:** The server extracts the nullifier from the spend proof \
          \and atomically checks it against a persistent store (SQLite). If the nullifier \
          \has been seen before, HTTP 409 (Conflict) is returned."
        , ""
        , "**Errors:** HTTP 422 for validation failures (wrong token type, key ID mismatch, \
          \challenge digest mismatch, invalid proof). HTTP 409 for double-spend attempts."
        ]
      ])
  <>
  extraInfo
    (Proxy :: Proxy ("issuer-directory" :> Get '[JSON] IssuerDirectory))
    (defAction & notes <>~
      [ DocNote "Issuer Directory"
        [ "Returns public metadata about this issuer as JSON. Clients use this \
          \to discover the issuer's public key and configuration before initiating \
          \the issuance protocol."
        , ""
        , "Fields:"
        , "- token_type: Always 0xE5AD (ACT Ristretto255, per IANA Privacy Pass Token Type registry)"
        , "- issuer_name: The issuer's hostname"
        , "- origin_info: The origin identifier"
        , "- credential_context: Hex-encoded context (0 or 32 bytes), used to bind credentials to a specific context (e.g., time window)"
        , "- issuer_key_id: Hex-encoded SHA-256 hash of the serialized issuer public key (Section 5 of draft-schlesinger-privacypass-act)"
        , "- public_key: Hex-encoded CBOR serialized issuer public key"
        , "- initial_credits: Number of credits issued per credential"
        ]
      ])

-- ---------------------------------------------------------------------------
-- Documentation generation
-- ---------------------------------------------------------------------------

apiDocs :: API
apiDocs = docsWith defaultDocOptions
  [ DocIntro "Privacy Pass ACT Server API"
    [ "This server implements the issuance and redemption protocols for \
      \Anonymous Credit Tokens (ACT) as specified in \
      \draft-schlesinger-privacypass-act \
      \(https://samuelschlesinger.github.io/draft-act/draft-schlesinger-privacypass-act.html)."
    , ""
    , "The underlying cryptographic scheme is defined in \
      \draft-schlesinger-cfrg-act \
      \(https://samuelschlesinger.github.io/ietf-anonymous-credit-tokens/draft-schlesinger-cfrg-act.html)."
    , ""
    , "The server acts as a joint Issuer and Origin (Section 4 of RFC 9576). \
      \Tokens are not publicly verifiable; the same entity that issues credentials \
      \also verifies spend proofs and issues refunds."
    ]
  , DocIntro "Protocol Flow"
    [ "1. Issuance: Client sends POST /token-request with a TokenRequest. \
      \Server responds with a TokenResponse containing an IssueResponse. \
      \Client finalizes the credential locally."
    , ""
    , "2. Redemption: Client spends credits by sending POST /token-redeem \
      \with a Token containing a spend proof. Server verifies the proof, checks \
      \the nullifier for double-spend, and returns a Refund. Client constructs \
      \a new credential with the remaining balance."
    , ""
    , "3. Discovery: Client queries GET /issuer-directory to obtain the \
      \issuer's public key and configuration."
    , ""
    , "Each credential can only be spent once. After spending, the client receives \
      \a refunded credential with the remaining balance, enforcing strict \
      \serialization of operations (concurrency control)."
    ]
  , DocIntro "Token Type"
    [ "This server uses token type 0xE5AD (ACT Ristretto255), registered in \
      \the IANA Privacy Pass Token Type registry with Nid = 32."
    ]
  ]
  extra
  actAPI

apiMarkdown :: String
apiMarkdown = markdown apiDocs
