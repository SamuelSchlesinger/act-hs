{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TypeOperators #-}
module ACT.API
  ( ACTAPI
  , actAPI
  ) where

import ACT.ContentTypes (PrivateCredentialRequest, PrivateCredentialResponse)
import ACT.Types (IssuerDirectory)

import qualified Data.ByteString.Lazy as LBS
import Data.Proxy (Proxy(..))
import Servant.API

type ACTAPI =
       "token-request"
         :> ReqBody '[PrivateCredentialRequest] LBS.ByteString
         :> Post '[PrivateCredentialResponse] LBS.ByteString
  :<|> "token-redeem"
         :> ReqBody '[OctetStream] LBS.ByteString
         :> Post '[OctetStream] LBS.ByteString
  :<|> "issuer-directory"
         :> Get '[JSON] IssuerDirectory

actAPI :: Proxy ACTAPI
actAPI = Proxy
