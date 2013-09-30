{-# LANGUAGE OverloadedStrings #-}
module Main where
import Graphics.UI.Gtk hiding (toClipboard)
import Control.Concurrent
import qualified Himitsu.PasswordStore as PS
import Himitsu.Database (ServiceName)
import Himitsu.Credentials
import System.Exit
import Data.String
import Control.Applicative
import Control.Monad
import AppState
import Himitsu.Config
import PasswordDialogs
import SettingsWindow
import MenuUtils
import Data.Maybe (fromJust)

main = do
  initGUI
  i <- statusIconNewFromFile systrayIconFile
  st <- getAppState
  case st of
    NoDB -> firstRunDialog
    _    -> return ()

  statusIconSetVisible i True
  i `on` statusIconPopupMenu $ \_ _ -> do
    i `seq` openMainMenu
  i `on` statusIconActivate $ do
    st <- getAppState
    case st of
      Locked ps -> settingsWindow ps
      _         -> return ()
  mainGUI

-- | Open the application's main menu. Normally brought up by right clicking
--   on the status icon.
openMainMenu :: IO ()
openMainMenu = do
  st <- getAppState
  case st of
    Locked ps -> do
      m <- menuNew
      addItem "Manage Passwords" m $ settingsWindow ps
      addItem "Open Database" m (openDatabaseDialog ps)
      addItem "Create New Database" m newDatabaseDialog
      separatorMenuItemNew >>= menuShellAppend m
      addItem "Exit" m exitSuccess
      menuPopup m Nothing
    _ -> do
      m <- menuNew
      addItem "Exit" m exitSuccess
      menuPopup m Nothing

-- | Bring up a dialog to re-initialize the password database.
newDatabaseDialog :: IO ()
newDatabaseDialog = do
    dlg <- fileChooserDialogNew Nothing
                                Nothing
                                FileChooserActionSave
                                [("Cancel", ResponseCancel),
                                 ("Create Database", ResponseAccept)]
    res <- dialogRun dlg
    mf <- fileChooserGetFilename dlg
    widgetDestroy dlg
    when (res == ResponseAccept) $ do
      let Just f = mf
      requestNewPassword msg Nothing >>= maybe (return ()) (create f)
  where
    create f pass = do
      PS.new pass f >>= PS.lock >>= setAppState . Locked
      setConf $ \c -> c {cfgDBFile = f}
      dlg <- messageDialogNew Nothing
                              [DialogModal]
                              MessageInfo
                              ButtonsOk
                              "New database created successfully!"
      dialogRun dlg
      widgetDestroy dlg
    msg = "Please enter a password to protect your new database."

-- | Bring up a dialog to open another database.
openDatabaseDialog :: PS.PasswordStore a -> IO ()
openDatabaseDialog ps = do
    dlg <- fileChooserDialogNew Nothing
                                Nothing
                                FileChooserActionOpen
                                [("Cancel", ResponseCancel),
                                 ("Open Database", ResponseAccept)]
    PS.getBackingFile ps >>= fileChooserSetFilename dlg
    res <- dialogRun dlg
    mf <- fileChooserGetFilename dlg
    widgetDestroy dlg
    when (res == ResponseAccept) $ do
      let Just f = mf
      open f
      setConf $ \c -> c {cfgDBFile = f}
      dlg <- messageDialogNew Nothing
                              [DialogModal]
                              MessageInfo
                              ButtonsOk
                              (changeOK f)
      dialogRun dlg
      widgetDestroy dlg
  where
    open f = PS.open f >>= setAppState . Locked . fromJust
    msg = "Please enter a password to protect your new database."
    changeOK f = "Database " ++ f ++ " loaded successfully!"

-- | Bring up a dialog to initialize the database if none were found.
--   Shown at first run.
firstRunDialog :: IO ()
firstRunDialog = do
    requestNewPassword msg Nothing >>= maybe (return ()) (updateState)
  where
    updateState pass = PS.new pass passwordDBFile >>= setAppState . Unlocked
    msg = "Welcome to Himitsu, the Haskell password manager!\n"
         ++ "Please enter a (strong!) password for your password database "
         ++ "to get started."
