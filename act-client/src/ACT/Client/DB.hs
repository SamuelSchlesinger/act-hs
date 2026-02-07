{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeOperators #-}
module ACT.Client.DB
  ( ServerConfig(..)
  , initClientDB
  , saveServerConfig
  , loadServerConfig
  , saveCredential
  , loadActiveCredential
  , deleteCredentials
  ) where

import Data.ByteString (ByteString)
import Data.Word (Word64)
import Database.SQLite.Simple

data ServerConfig = ServerConfig
  { scServerUrl         :: !String
  , scIssuerName        :: !ByteString
  , scOriginInfo        :: !ByteString
  , scCredentialContext  :: !ByteString
  , scIssuerKeyId       :: !ByteString
  , scPublicKey         :: !ByteString
  , scInitialCredits    :: !Word64
  , scDefaultCost       :: !Word64
  , scParamsOrg         :: !String
  , scParamsSvc         :: !String
  , scParamsDep         :: !String
  , scParamsVer         :: !String
  } deriving (Show)

initClientDB :: Connection -> IO ()
initClientDB conn = do
  execute_ conn "PRAGMA journal_mode=WAL"
  execute_ conn
    "CREATE TABLE IF NOT EXISTS server_config (\
    \  id                  INTEGER PRIMARY KEY CHECK (id = 1),\
    \  server_url          TEXT NOT NULL,\
    \  issuer_name         BLOB NOT NULL,\
    \  origin_info         BLOB NOT NULL,\
    \  credential_context  BLOB NOT NULL,\
    \  issuer_key_id       BLOB NOT NULL,\
    \  public_key          BLOB NOT NULL,\
    \  initial_credits     INTEGER NOT NULL,\
    \  default_cost        INTEGER NOT NULL,\
    \  params_org          TEXT NOT NULL,\
    \  params_svc          TEXT NOT NULL,\
    \  params_dep          TEXT NOT NULL,\
    \  params_ver          TEXT NOT NULL\
    \)"
  execute_ conn
    "CREATE TABLE IF NOT EXISTS credentials (\
    \  id          INTEGER PRIMARY KEY AUTOINCREMENT,\
    \  credential  BLOB NOT NULL,\
    \  credits     INTEGER NOT NULL,\
    \  created_at  TEXT DEFAULT (datetime('now')),\
    \  active      INTEGER DEFAULT 1\
    \)"

saveServerConfig :: Connection -> ServerConfig -> IO ()
saveServerConfig conn sc = do
  execute_ conn "DELETE FROM server_config WHERE id = 1"
  execute conn
    "INSERT INTO server_config \
    \(id, server_url, issuer_name, origin_info, credential_context, \
    \issuer_key_id, public_key, initial_credits, default_cost, \
    \params_org, params_svc, params_dep, params_ver) \
    \VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
    ( ( scServerUrl sc
      , scIssuerName sc
      , scOriginInfo sc
      , scCredentialContext sc
      , scIssuerKeyId sc
      , scPublicKey sc
      ) :. ( scInitialCredits sc
           , scDefaultCost sc
           , scParamsOrg sc
           , scParamsSvc sc
           , scParamsDep sc
           , scParamsVer sc
           )
    )

loadServerConfig :: Connection -> IO (Maybe ServerConfig)
loadServerConfig conn = do
  rows <- query_ conn
    "SELECT server_url, issuer_name, origin_info, credential_context, \
    \issuer_key_id, public_key, initial_credits, default_cost, \
    \params_org, params_svc, params_dep, params_ver \
    \FROM server_config WHERE id = 1"
    :: IO [((String, ByteString, ByteString, ByteString, ByteString, ByteString)
           :. (Word64, Word64, String, String, String, String))]
  case rows of
    [((url, iName, oInfo, cCtx, kId, pk) :. (ic, dc, pOrg, pSvc, pDep, pVer))] ->
      return $ Just ServerConfig
        { scServerUrl        = url
        , scIssuerName       = iName
        , scOriginInfo       = oInfo
        , scCredentialContext = cCtx
        , scIssuerKeyId      = kId
        , scPublicKey        = pk
        , scInitialCredits   = ic
        , scDefaultCost      = dc
        , scParamsOrg        = pOrg
        , scParamsSvc        = pSvc
        , scParamsDep        = pDep
        , scParamsVer        = pVer
        }
    _ -> return Nothing

saveCredential :: Connection -> ByteString -> Word64 -> IO ()
saveCredential conn cred credits = do
  execute_ conn "UPDATE credentials SET active = 0 WHERE active = 1"
  execute conn
    "INSERT INTO credentials (credential, credits) VALUES (?, ?)"
    (cred, credits)

loadActiveCredential :: Connection -> IO (Maybe (ByteString, Word64))
loadActiveCredential conn = do
  rows <- query_ conn
    "SELECT credential, credits FROM credentials WHERE active = 1 ORDER BY id DESC LIMIT 1"
    :: IO [(ByteString, Word64)]
  case rows of
    [(cred, credits)] -> return $ Just (cred, credits)
    _                 -> return Nothing

deleteCredentials :: Connection -> IO ()
deleteCredentials conn =
  execute_ conn "DELETE FROM credentials"
