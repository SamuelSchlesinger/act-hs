module ACT.Client.HTTP
  ( tokenRequestC
  , tokenRedeemC
  , issuerDirectoryC
  , fetchIssuerDirectory
  , requestCredential
  , redeemToken
  ) where

import ACT.API (ACTAPI)
import ACT.Types (IssuerDirectory)

import Data.Proxy (Proxy(..))
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as LBS
import Servant.API ((:<|>)(..))
import Servant.Client (ClientEnv, ClientM, client, runClientM)

tokenRequestC :: LBS.ByteString -> ClientM LBS.ByteString
tokenRedeemC :: LBS.ByteString -> ClientM LBS.ByteString
issuerDirectoryC :: ClientM IssuerDirectory
(tokenRequestC :<|> tokenRedeemC :<|> issuerDirectoryC) = client (Proxy :: Proxy ACTAPI)

fetchIssuerDirectory :: ClientEnv -> IO IssuerDirectory
fetchIssuerDirectory env = do
  result <- runClientM issuerDirectoryC env
  case result of
    Right dir -> return dir
    Left err  -> fail $ "Failed to fetch issuer directory: " ++ show err

requestCredential :: ClientEnv -> BS.ByteString -> IO BS.ByteString
requestCredential env tokenReqBytes = do
  result <- runClientM (tokenRequestC (LBS.fromStrict tokenReqBytes)) env
  case result of
    Right bs -> return (LBS.toStrict bs)
    Left err -> fail $ "Token request failed: " ++ show err

redeemToken :: ClientEnv -> BS.ByteString -> IO BS.ByteString
redeemToken env tokenWireBytes = do
  result <- runClientM (tokenRedeemC (LBS.fromStrict tokenWireBytes)) env
  case result of
    Right bs -> return (LBS.toStrict bs)
    Left err -> fail $ "Token redeem failed: " ++ show err
