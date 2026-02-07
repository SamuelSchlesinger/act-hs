module Main (main) where

import ACT.Server.Docs (apiMarkdown)

main :: IO ()
main = putStrLn apiMarkdown
