module AppState (
    AppState (..), AppConf (..),
    setAppState, getAppState, lock, unlock, setConf, getConf
  ) where
import Data.Default
import Data.IORef
import System.IO.Unsafe
import System.Directory
import qualified Himitsu.PasswordStore as PS
import Himitsu.Credentials
import Himitsu.Config
import Graphics.UI.Gtk
import Control.Exception
import PasswordDialogs
import System.IO

data AppConf = AppConf {
    cfgDBFile           :: FilePath,
    cfgClipboardTimeout :: Timeout
  } deriving (Show, Read)

instance Default AppConf where
  def = AppConf {
      cfgDBFile = passwordDBFile,
      cfgClipboardTimeout = MSecs 60000
    }

data AppState
  = Locked (PS.PasswordStore PS.Locked)
  | Unlocked (PS.PasswordStore PS.Unlocked)
  | NoDB

{-# NOINLINE appState #-}
appState :: IORef AppState
appState = unsafePerformIO $ do
  file <- getConf cfgDBFile
  mdb <- PS.open file
  case mdb of
    Just db -> newIORef (Locked db)
    _       -> newIORef NoDB

{-# NOINLINE appConf #-}
appConf :: IORef AppConf
appConf = unsafePerformIO $ do
  ex <- doesFileExist confFile
  if ex
    then do
      conf <- reads `fmap` readFile confFile
      case conf of
        [(conf', _)] -> newIORef conf'
        _            -> newIORef def
    else do
      newIORef def

-- | Get a configuration parameter.
getConf :: (AppConf -> a) -> IO a
getConf f = f `fmap` readIORef appConf

-- | Set a configuration parameter, then save to disk.
setConf :: (AppConf -> AppConf) -> IO ()
setConf f = do
  atomicModifyIORef' appConf (\cfg -> (f cfg, ()))
  cfg <- readIORef appConf
  (tmpfile, h) <- openBinaryTempFile appDataDir "passwords.db"
  hPutStrLn h $ show cfg
  hClose h
  renameFile tmpfile confFile


-- | Set the app state.
setAppState :: AppState -> IO ()
setAppState st = writeIORef appState st

-- | Get the app state.
getAppState :: IO AppState
getAppState = readIORef appState

withFailure :: IO () -> IO ()
withFailure m = catch m $ \err -> do
  let msg = show (err :: SomeException)
  dlg <- messageDialogNew Nothing [DialogModal] MessageError ButtonsOk msg
  _ <- dialogRun dlg
  widgetDestroy dlg

-- | Ask the user for a password, then use that password to unlock the app
--   state.
unlock :: PS.PasswordStore PS.Locked -> IO ()
unlock ps = withFailure $ do
    _ <- requestPassword msg $ \pass -> do
      mps <- PS.unlock ps pass
      case mps of
        Just ps' -> do
          setAppState (Unlocked ps')
          return (Right ())
        _ -> do
          return (Left badPass)
    return ()
  where
    msg = "Enter your password to unlock your password store."
    badPass = "The password you entered was incorrect; please try again."

-- | Set the app state to locked.
lock :: PS.PasswordStore PS.Unlocked -> IO ()
lock ps = withFailure $ do
  ps' <- PS.lock ps
  setAppState (Locked ps')
