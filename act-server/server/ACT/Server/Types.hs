{-# LANGUAGE OverloadedStrings #-}
module ACT.Server.Types
  ( ServerState(..)
  , IssuerDirectory(..)
  ) where

import Crypto.AnonymousCreditTokens.Types (Params, PrivateKey, PublicKey)

import Data.Aeson (FromJSON(..), ToJSON(..), object, (.=), withObject, (.:))
import Data.ByteString (ByteString)
import Data.Text (Text)
import Data.Word (Word16, Word64)
import Database.SQLite.Simple (Connection)

data ServerState = ServerState
  { ssPrivateKey        :: !PrivateKey
  , ssPublicKey         :: !PublicKey
  , ssParams            :: !Params
  , ssConn              :: !Connection
  , ssIssuerName        :: !ByteString
  , ssOriginInfo        :: !ByteString
  , ssCredentialContext  :: !ByteString
  , ssIssuerKeyId       :: !ByteString
  , ssInitialCredits    :: !Word64
  }

data IssuerDirectory = IssuerDirectory
  { idTokenType         :: !Word16
  , idIssuerName        :: !Text
  , idOriginInfo        :: !Text
  , idCredentialContext  :: !Text
  , idIssuerKeyId       :: !Text
  , idPublicKey         :: !Text
  , idInitialCredits    :: !Word64
  }

instance ToJSON IssuerDirectory where
  toJSON d = object
    [ "token_type"         .= idTokenType d
    , "issuer_name"        .= idIssuerName d
    , "origin_info"        .= idOriginInfo d
    , "credential_context" .= idCredentialContext d
    , "issuer_key_id"      .= idIssuerKeyId d
    , "public_key"         .= idPublicKey d
    , "initial_credits"    .= idInitialCredits d
    ]

instance FromJSON IssuerDirectory where
  parseJSON = withObject "IssuerDirectory" $ \o -> IssuerDirectory
    <$> o .: "token_type"
    <*> o .: "issuer_name"
    <*> o .: "origin_info"
    <*> o .: "credential_context"
    <*> o .: "issuer_key_id"
    <*> o .: "public_key"
    <*> o .: "initial_credits"
