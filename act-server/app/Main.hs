{-# LANGUAGE OverloadedStrings #-}
module Main (main) where

import ACT.Server.API (actAPI)
import ACT.Server.Config (Config(..), parseConfig)
import ACT.Server.Crypto (issuerKeyId)
import ACT.Server.DB (initDB, loadOrCreateKeyPair)
import ACT.Server.Handlers (server)
import ACT.Server.Types (ServerState(..))

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
        { ssPrivateKey       = sk
        , ssPublicKey        = pk
        , ssParams           = params
        , ssConn             = conn
        , ssIssuerName       = cfgIssuerName cfg
        , ssOriginInfo       = cfgOriginInfo cfg
        , ssCredentialContext = cfgCredentialContext cfg
        , ssIssuerKeyId      = keyId
        , ssInitialCredits   = cfgInitialCredits cfg
        }

  putStrLn $ "ACT server listening on port " ++ show (cfgPort cfg)
  run (cfgPort cfg) (serve actAPI (server st))
