-- | Application configuration for Hasswords.
module Himitsu.Config where
import System.Directory
import System.FilePath
import System.IO.Unsafe
import Paths_himitsu

appName :: String
appName = "himitsu"

{-# NOINLINE appDataDir #-}
appDataDir :: FilePath
appDataDir = unsafePerformIO $ do
  datadir <- getAppUserDataDirectory appName
  createDirectoryIfMissing True datadir
  return datadir

-- | Default database file name. The user may change this in the config.
passwordDBFile :: FilePath
passwordDBFile = appDataDir </> "passwords.db"

-- | Path to config file. The user may not change this.
confFile :: FilePath
confFile = appDataDir </> "config"

{-# NOINLINE systrayIconFile #-}
systrayIconFile :: FilePath
systrayIconFile = unsafePerformIO $ getDataFileName "hi.png"
