{-# LANGUAGE OverloadedStrings #-}
module ACT.Server.DB
  ( initDB
  , loadOrCreateKeyPair
  , checkAndStoreNullifier
  , lookupStoredRefund
  , expireOldNullifiers
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
    \  nullifier   BLOB PRIMARY KEY NOT NULL,\
    \  context     BLOB,\
    \  proof_hash  BLOB,\
    \  refund_data BLOB,\
    \  created_at  TEXT DEFAULT (datetime('now'))\
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

-- | Atomically check and store a nullifier with context, proof hash, and refund data.
-- Returns True if the nullifier was successfully stored (i.e., not a duplicate).
checkAndStoreNullifier :: Connection -> ByteString -> ByteString -> ByteString -> ByteString -> IO Bool
checkAndStoreNullifier conn nullifier context proofHash refundData = do
  execute conn "INSERT OR IGNORE INTO nullifiers (nullifier, context, proof_hash, refund_data) VALUES (?, ?, ?, ?)"
    (nullifier, context, proofHash, refundData)
  changes conn >>= \n -> return (n > 0)

-- | Look up a previously stored proof hash and refund by nullifier (for idempotent retry).
lookupStoredRefund :: Connection -> ByteString -> IO (Maybe (ByteString, ByteString))
lookupStoredRefund conn nullifier = do
  rows <- query conn "SELECT proof_hash, refund_data FROM nullifiers WHERE nullifier = ?"
    (Only nullifier) :: IO [(ByteString, ByteString)]
  case rows of
    [(ph, rd)] -> return (Just (ph, rd))
    _          -> return Nothing

-- | Delete nullifiers older than the given number of seconds.
expireOldNullifiers :: Connection -> Int -> IO ()
expireOldNullifiers conn ttlSeconds =
  execute conn
    "DELETE FROM nullifiers WHERE created_at < datetime('now', ?)"
    (Only ("-" ++ show ttlSeconds ++ " seconds"))
