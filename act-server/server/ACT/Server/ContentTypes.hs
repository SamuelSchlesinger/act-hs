{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE OverloadedStrings #-}
module ACT.Server.ContentTypes
  ( PrivateCredentialRequest
  , PrivateCredentialResponse
  ) where

import qualified Data.ByteString.Lazy as LBS
import Data.Typeable (Typeable)
import Network.HTTP.Media ((//))
import Servant.API (Accept(..), MimeRender(..), MimeUnrender(..))

data PrivateCredentialRequest deriving Typeable

instance Accept PrivateCredentialRequest where
  contentType _ = "application" // "private-credential-request"

instance MimeRender PrivateCredentialRequest LBS.ByteString where
  mimeRender _ = id

instance MimeUnrender PrivateCredentialRequest LBS.ByteString where
  mimeUnrender _ = Right

data PrivateCredentialResponse deriving Typeable

instance Accept PrivateCredentialResponse where
  contentType _ = "application" // "private-credential-response"

instance MimeRender PrivateCredentialResponse LBS.ByteString where
  mimeRender _ = id

instance MimeUnrender PrivateCredentialResponse LBS.ByteString where
  mimeUnrender _ = Right
