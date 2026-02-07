{-# LANGUAGE OverloadedStrings #-}
module ACT.Server.DB
  ( initDB
  , loadOrCreateKeyPair
  , checkAndStoreNullifier
  ) where

import Crypto.AnonymousCreditTokens (generatePrivateKey, publicKey)
import Crypto.AnonymousCreditTokens.Types (PrivateKey(..), PublicKey(..))

import Data.ByteString (ByteString)
import Database.SQLite.Simple

-- | Initialize the database schema.
initDB :: Connection -> IO ()
initDB conn = do
  execute_ conn "PRAGMA journal_mode=WAL"
  execute_ conn
    "CREATE TABLE IF NOT EXISTS issuer_keys (\
    \  id          INTEGER PRIMARY KEY CHECK (id = 1),\
    \  private_key BLOB NOT NULL,\
    \  public_key  BLOB NOT NULL\
    \)"
  execute_ conn
    "CREATE TABLE IF NOT EXISTS nullifiers (\
    \  nullifier  BLOB PRIMARY KEY NOT NULL,\
    \  context    BLOB,\
    \  created_at TEXT DEFAULT (datetime('now'))\
    \)"

-- | Load the key pair from row 1, or generate and insert a new one.
loadOrCreateKeyPair :: Connection -> IO (PrivateKey, PublicKey)
loadOrCreateKeyPair conn = do
  rows <- query_ conn "SELECT private_key, public_key FROM issuer_keys WHERE id = 1"
    :: IO [(ByteString, ByteString)]
  case rows of
    [(skBs, pkBs)] -> return (PrivateKey skBs, PublicKey pkBs)
    _ -> do
      sk@(PrivateKey skBs) <- generatePrivateKey
      let pk@(PublicKey pkBs) = publicKey sk
      execute conn "INSERT INTO issuer_keys (id, private_key, public_key) VALUES (1, ?, ?)"
        (skBs, pkBs)
      return (sk, pk)

-- | Atomically check and store a nullifier. Returns True if the nullifier
-- was successfully stored (i.e., not a duplicate).
checkAndStoreNullifier :: Connection -> ByteString -> IO Bool
checkAndStoreNullifier conn nullifier = do
  execute conn "INSERT OR IGNORE INTO nullifiers (nullifier) VALUES (?)" (Only nullifier)
  changes conn >>= \n -> return (n > 0)
