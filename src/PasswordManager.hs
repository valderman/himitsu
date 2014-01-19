-- | The password manager window.
module PasswordManager where
import Control.Monad
import Graphics.UI.Gtk hiding (toClipboard)
import qualified Himitsu.PasswordStore as PS
import Himitsu.Credentials
import Himitsu.PasswordUtils
import Himitsu.PasswordFile (ServiceName)
import MenuUtils
import Control.Monad.IO.Class
import PasswordGenerator
import Data.String
import AppState

-- | Build a context menu for display when right-clicking the password list.
contextMenu :: PS.PasswordStore PS.Unlocked
            -> ListStore (ServiceName, Credentials)
            -> TreeView
            -> Window
            -> IO Menu
contextMenu ps model view window = do
  m <- menuNew
  addItem "Copy password" m (copyPassword model view)
  addItem "Change password" m (updatePasswordDialog ps model view)
  addItem "Delete password" m (deletePassword ps model view window)
  separatorMenuItemNew >>= menuShellAppend m
  addItem "Add password" m (addPasswordDialog ps model)
  return m

-- | Copy the selected password to the clipboard, with a one minut timeout
--   until it is erased.
copyPassword :: ListStore (ServiceName, Credentials) -> TreeView -> IO ()
copyPassword model view = do
  withSelectedItem model view $ \_ (_, (Credentials _ p)) -> do
    timeout <- getConf cfgClipboardTimeout
    toClipboard timeout p

-- | Update the password list.
updatePasswords :: PS.PasswordStore PS.Unlocked
                -> ListStore (ServiceName, Credentials)
                -> IO ()
updatePasswords ps model = do
  pwds <- PS.list ps
  listStoreClear model
  forM_ pwds (listStoreAppend model)

-- | Perform an action on the currently selected item, if any. If no item is
--   selected, display a warning about that instead.
withSelectedItem :: ListStore (ServiceName, Credentials)
                 -> TreeView
                 -> (Int -> (ServiceName, Credentials) -> IO ())
                 -> IO ()
withSelectedItem model view f = do
  s <- treeViewGetSelection view
  ixs <- treeSelectionGetSelectedRows s
  case ixs of
    [[ix]] -> listStoreGetValue model ix >>= f ix
    _      -> do
      dlg <- messageDialogNew Nothing
                              [DialogModal]
                              MessageInfo
                              ButtonsOk
                              msgText
      _ <- dialogRun dlg
      widgetDestroy dlg
  where
    msgText = "You must select an item to do that."

-- | Delete a password after obtaining confirmation from the user.
deletePassword :: PS.PasswordStore PS.Unlocked
               -> ListStore (ServiceName, Credentials)
               -> TreeView
               -> Window
               -> IO ()
deletePassword ps model view window = do
  withSelectedItem model view $ \ix (s, _) -> do
    let msgText = "Really delete password for " ++ show s ++ "? " ++
                  "Once deleted, your password will be gone forever and " ++
                  "can not be recovered."
    dlg <- messageDialogNew (Just window)
                            [DialogModal]
                            MessageWarning
                            ButtonsYesNo
                            msgText
    res <- dialogRun dlg
    when (res == ResponseYes) $ do
      PS.delete ps ix
      listStoreRemove model ix
    widgetDestroy dlg

-- | Create a list view containing all the accounts currently in the password
--   store.
passwordManager :: Window -> PS.PasswordStore PS.Unlocked -> IO (VBox, IO ())
passwordManager window ps = do
    pwds <- PS.list ps 
    lst <- listStoreNew pwds
    r <- cellRendererTextNew
    
    services <- treeViewColumnNew
    cellLayoutPackStart services r False
    cellLayoutSetAttributes services r lst $
      \(s, _) -> [cellText := show s]
    treeViewColumnSetTitle services "Service"
    treeViewColumnSetMinWidth services 150
  
    names <- treeViewColumnNew
    cellLayoutPackStart names r False
    cellLayoutSetAttributes names r lst $
      \(_, c) -> [cellText := showName c]
    treeViewColumnSetTitle names "Username"
    treeViewColumnSetMinWidth names 150
  
    strength <- treeViewColumnNew
    cellLayoutPackStart strength r False
    cellLayoutSetAttributes strength r lst $
      \(_, c) -> [cellText := if hasPassword c
                                then show (judge $ analyze c)
                                else "No password!"]
    treeViewColumnSetTitle strength "Password Strength"
    treeViewColumnSetMinWidth strength 80

    pwdlist <- treeViewNewWithModel lst
    _ <- treeViewAppendColumn pwdlist services
    _ <- treeViewAppendColumn pwdlist names
    _ <- treeViewAppendColumn pwdlist strength
    
    scrollwindow <- scrolledWindowNew Nothing Nothing
    scrolledWindowSetPolicy scrollwindow PolicyNever PolicyAutomatic
    containerAdd scrollwindow pwdlist
    
    vbox <- vBoxNew False 5
    containerAdd vbox scrollwindow
    set vbox [boxChildPacking pwdlist := PackGrow]

    ctxmenu <- contextMenu ps lst pwdlist window
    _ <- pwdlist `on` buttonPressEvent $ do
      btn <- eventButton
      when (btn == RightButton) $ do
        liftIO $ menuPopup ctxmenu Nothing
      return False
    
    return (vbox, addPasswordDialog ps lst)
  where
    showName = show . entUsername

-- | Bring up a dialog for adding a new password to the store.
addPasswordDialog :: PS.PasswordStore PS.Unlocked
                  -> ListStore (ServiceName, Credentials)
                  -> IO ()
addPasswordDialog ps model = do
  dlg <- dialogNew
  _ <- dialogAddButton dlg "Cancel" ResponseReject
  _ <- dialogAddButton dlg "Add account" ResponseAccept

  vbox <- dialogGetUpper dlg
  (box, serviceent, userent, passent) <- newPasswordBox dlg
  containerAdd vbox box
  widgetShowAll vbox
  res <- dialogRun dlg
  case res of
    ResponseAccept -> do
      svc <- entryGetText serviceent
      user <- entryGetText userent
      pass <- entryGetText passent
      _ <- PS.add ps (fromString svc)
                     (Credentials (fromString user) (fromString pass))
      updatePasswords ps model
    _ -> do
      return ()
  widgetDestroy dlg

-- | Bring up a dialog to update the account details for an entry in the
--   password store.
updatePasswordDialog :: PS.PasswordStore PS.Unlocked
                     -> ListStore (ServiceName, Credentials)
                     -> TreeView
                     -> IO ()
updatePasswordDialog ps model view = do
  withSelectedItem model view $ \ix (s, Credentials u p) -> do
    dlg <- dialogNew
    _ <- dialogAddButton dlg "Cancel" ResponseReject
    _ <- dialogAddButton dlg "Update password" ResponseAccept

    vbox <- dialogGetUpper dlg
    (box, serviceent, userent, passent) <- newPasswordBox dlg
    entrySetText serviceent (show s)
    entrySetText userent (show u)
    entrySetText passent (show p)
    containerAdd vbox box
    widgetShowAll vbox
    res <- dialogRun dlg
    case res of
      ResponseAccept -> do
        svc <- entryGetText serviceent
        user <- entryGetText userent
        pass <- entryGetText passent
        _ <- PS.update ps ix $ Credentials (fromString user) (fromString pass)
        let s' = fromString svc
        when (s' /= s) $ do
          _ <- PS.rename ps ix s'
          return ()
        updatePasswords ps model
      _ -> do
        return ()
    widgetDestroy dlg
