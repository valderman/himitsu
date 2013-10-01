module SettingsWindow (settingsWindow) where
import Graphics.UI.Gtk
import PasswordManager
import PasswordDialogs
import qualified Himitsu.PasswordStore as PS
import AppState
import MenuUtils

-- | Bring up the settings window. Basically only the password list.
settingsWindow :: PS.PasswordStore PS.Locked -> IO ()
settingsWindow ps = do
  unlock ps
  st <- getAppState
  case st of
    Unlocked ps' -> do
      window <- windowNew
      box <- vBoxNew False 5
      set window [containerChild := box]

      (manager, addPassDlg) <- passwordManager window ps'
      
      -- Build menu
      mb <- menuBarNew
      m <- menuNew
      addItem "Add Password" m addPassDlg
      addItem "Change Master Password" m (changePassDialog ps')
      addItem "Lock database" m (widgetDestroy window)
      separatorMenuItemNew >>= menuShellAppend m
      addItem "Exit" m mainQuit
      dbmenu <- menuItemNewWithLabel "Database"
      menuItemSetSubmenu dbmenu m
      menuShellAppend mb dbmenu
      
      -- Stuff everything into the box
      containerAdd box mb
      containerAdd box manager
      set box [boxChildPacking mb := PackNatural]
      widgetSetSizeRequest window 465 300
      _ <- window `onDestroy` lock ps'
      widgetShowAll window
      return ()
    _ ->
      return ()

-- | Bring up a dialog to change the master password for the password store.
changePassDialog :: PS.PasswordStore PS.Unlocked -> IO ()
changePassDialog ps = do
    requestNewPassword msg Nothing >>= maybe (return ()) (updateState)
  where
    updateState pass = do
      _ <- PS.changePass ps pass
      dlg <- messageDialogNew Nothing
                              [DialogModal]
                              MessageInfo
                              ButtonsOk
                              changeOK
      _ <- dialogRun dlg
      widgetDestroy dlg
    msg = "Please enter a new password."
    changeOK = "Password changed! " ++
               "Don't forget it, or your database will be lost."


-- TODO: lägg till meny med add account, change password, molnsaker, etc.
