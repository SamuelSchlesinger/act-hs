module ACT.Server.Config
  ( Config(..)
  , parseConfig
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as B16
import Data.Word (Word64)
import Options.Applicative

data Config = Config
  { cfgPort              :: !Int
  , cfgDBPath            :: !FilePath
  , cfgIssuerName        :: !ByteString
  , cfgOriginInfo        :: !ByteString
  , cfgCredentialContext  :: !ByteString
  , cfgInitialCredits    :: !Word64
  , cfgParamsOrg         :: !String
  , cfgParamsSvc         :: !String
  , cfgParamsDep         :: !String
  , cfgParamsVer         :: !String
  , cfgDefaultCost       :: !Word64
  , cfgNullifierTTL      :: !(Maybe Int)
  } deriving (Show)

parseConfig :: IO Config
parseConfig = execParser opts
  where
    opts = info (configParser <**> helper)
      ( fullDesc
     <> progDesc "Privacy Pass ACT Server"
      )

configParser :: Parser Config
configParser = Config
  <$> option auto
      ( long "port"
     <> metavar "PORT"
     <> value 8080
     <> showDefault
     <> help "Listen port"
      )
  <*> strOption
      ( long "db"
     <> metavar "PATH"
     <> value "act-server.db"
     <> showDefault
     <> help "SQLite database path"
      )
  <*> (encodeUtf8' <$> strOption
      ( long "issuer-name"
     <> metavar "NAME"
     <> help "Issuer hostname"
      ))
  <*> (encodeUtf8' <$> strOption
      ( long "origin-info"
     <> metavar "INFO"
     <> help "Origin info"
      ))
  <*> option hexReader
      ( long "credential-context"
     <> metavar "HEX"
     <> value BS.empty
     <> help "Credential context (hex, 0 or 32 bytes)"
      )
  <*> option auto
      ( long "initial-credits"
     <> metavar "N"
     <> value 1000
     <> showDefault
     <> help "Credits per issuance"
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
  <*> option auto
      ( long "default-cost"
     <> metavar "N"
     <> value 1
     <> showDefault
     <> help "Expected spend amount per redemption"
      )
  <*> optional (option auto
      ( long "nullifier-ttl"
     <> metavar "SECONDS"
     <> help "Seconds before nullifiers/refunds expire"
      ))

encodeUtf8' :: String -> ByteString
encodeUtf8' = BS.pack . map (fromIntegral . fromEnum)

hexReader :: ReadM ByteString
hexReader = eitherReader $ \s ->
  if null s
    then Right BS.empty
    else case B16.decode (encodeUtf8' s) of
      Right bs
        | BS.length bs == 0 || BS.length bs == 32 -> Right bs
        | otherwise -> Left "credential-context must be 0 or 32 bytes"
      Left err -> Left $ "invalid hex: " ++ err
