{-# LANGUAGE OverloadedStrings #-}
module Main (main) where

import ACT.API (actAPI)
import ACT.Crypto (issuerKeyId)
import ACT.Server.Config (Config(..), parseConfig)
import ACT.Server.DB (initDB, loadOrCreateKeyPair, expireOldNullifiers)
import ACT.Server.Handlers (server)
import ACT.Server.Types (ServerState(..))

import Control.Concurrent (forkIO, threadDelay)
import Control.Monad (forever, void)
import Crypto.AnonymousCreditTokens (newParams)

import Database.SQLite.Simple (open)
import Network.Wai.Handler.Warp (run)
import Servant (serve)

main :: IO ()
main = do
  cfg <- parseConfig

  conn <- open (cfgDBPath cfg)
  initDB conn
  (sk, pk) <- loadOrCreateKeyPair conn

  params <- newParams
    (cfgParamsOrg cfg)
    (cfgParamsSvc cfg)
    (cfgParamsDep cfg)
    (cfgParamsVer cfg)

  let keyId = issuerKeyId pk
      st = ServerState
        { ssPrivateKey          = sk
        , ssPublicKey           = pk
        , ssParams              = params
        , ssConn                = conn
        , ssIssuerName          = cfgIssuerName cfg
        , ssOriginInfo          = cfgOriginInfo cfg
        , ssCredentialContext    = cfgCredentialContext cfg
        , ssIssuerKeyId         = keyId
        , ssInitialCredits      = cfgInitialCredits cfg
        , ssDefaultCost         = cfgDefaultCost cfg
        , ssNullifierTTLSeconds = cfgNullifierTTL cfg
        }

  -- Start background nullifier expiry thread if TTL is configured
  case cfgNullifierTTL cfg of
    Just ttl -> void $ forkIO $ forever $ do
      threadDelay (ttl * 1000000)  -- sleep for TTL seconds
      expireOldNullifiers conn ttl
    Nothing -> return ()

  putStrLn $ "ACT server listening on port " ++ show (cfgPort cfg)
  run (cfgPort cfg) (serve actAPI (server st))
