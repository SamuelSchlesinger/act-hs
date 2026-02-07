module ACT.Client.Config
  ( Command(..)
  , InitOpts(..)
  , SpendOpts(..)
  , parseCommand
  ) where

import Data.Word (Word64)
import Options.Applicative

data Command
  = Init InitOpts
  | Issue FilePath
  | Spend SpendOpts
  | Status FilePath
  deriving (Show)

data InitOpts = InitOpts
  { initServerUrl :: !String
  , initParamsOrg :: !String
  , initParamsSvc :: !String
  , initParamsDep :: !String
  , initParamsVer :: !String
  , initDBPath    :: !FilePath
  } deriving (Show)

data SpendOpts = SpendOpts
  { spendCost   :: !(Maybe Word64)
  , spendDBPath :: !FilePath
  } deriving (Show)

parseCommand :: IO Command
parseCommand = execParser opts
  where
    opts = info (commandParser <**> helper)
      ( fullDesc
     <> progDesc "Privacy Pass ACT Client"
      )

commandParser :: Parser Command
commandParser = subparser
  ( command "init"
    ( info (Init <$> initOptsParser)
      (progDesc "Initialize client: fetch issuer directory and store config")
    )
  <> command "issue"
    ( info (Issue <$> dbPathOption)
      (progDesc "Issue a new credential from the server")
    )
  <> command "spend"
    ( info (Spend <$> spendOptsParser)
      (progDesc "Spend credits from the active credential")
    )
  <> command "status"
    ( info (Status <$> dbPathOption)
      (progDesc "Show active credential status")
    )
  )

initOptsParser :: Parser InitOpts
initOptsParser = InitOpts
  <$> strOption
      ( long "server-url"
     <> metavar "URL"
     <> help "ACT server base URL (e.g. http://localhost:8080)"
      )
  <*> strOption
      ( long "params-org"
     <> metavar "STR"
     <> value "act-server"
     <> showDefault
     <> help "Params domain separator (org)"
      )
  <*> strOption
      ( long "params-svc"
     <> metavar "STR"
     <> value "privacy-pass"
     <> showDefault
     <> help "Params domain separator (svc)"
      )
  <*> strOption
      ( long "params-dep"
     <> metavar "STR"
     <> value "production"
     <> showDefault
     <> help "Params domain separator (dep)"
      )
  <*> strOption
      ( long "params-ver"
     <> metavar "STR"
     <> value "2026-01-01"
     <> showDefault
     <> help "Params domain separator (ver)"
      )
  <*> dbPathOption

spendOptsParser :: Parser SpendOpts
spendOptsParser = SpendOpts
  <$> optional (option auto
      ( long "cost"
     <> metavar "N"
     <> help "Credits to spend (defaults to server's default_cost)"
      ))
  <*> dbPathOption

dbPathOption :: Parser FilePath
dbPathOption = strOption
  ( long "db"
 <> metavar "PATH"
 <> value "act-client.db"
 <> showDefault
 <> help "SQLite database path"
  )
