{-# LANGUAGE OverloadedStrings #-}
module ACT.Server.Types
  ( ServerState(..)
  , IssuerDirectory(..)
  ) where

import ACT.Types (IssuerDirectory(..))

import Crypto.AnonymousCreditTokens.Types (Params, PrivateKey, PublicKey)

import Data.ByteString (ByteString)
import Data.Word (Word64)
import Database.SQLite.Simple (Connection)

data ServerState = ServerState
  { ssPrivateKey           :: !PrivateKey
  , ssPublicKey            :: !PublicKey
  , ssParams               :: !Params
  , ssConn                 :: !Connection
  , ssIssuerName           :: !ByteString
  , ssOriginInfo           :: !ByteString
  , ssCredentialContext     :: !ByteString
  , ssIssuerKeyId          :: !ByteString
  , ssInitialCredits       :: !Word64
  , ssDefaultCost          :: !Word64
  , ssNullifierTTLSeconds  :: !(Maybe Int)
  }
