-- | The password manager window.
module PasswordManager where
import Control.Monad
import Graphics.UI.Gtk hiding (toClipboard)
import qualified Himitsu.PasswordStore as PS
import Himitsu.Credentials
import Himitsu.PasswordUtils
import Himitsu.Database
import MenuUtils
import Control.Monad.IO.Class
import PasswordDialogs (passwordBox)
import PasswordGenerator
import Data.String
import Control.Monad.Reader
import Data.List

-- | Build a context menu for display when right-clicking the password list.
contextMenu :: PS.PasswordStore PS.Unlocked
            -> ListStore (ServiceName, Credentials)
            -> TreeView
            -> Window
            -> IO Menu
contextMenu ps model view window = do
  m <- menuNew
  addItem "Copy password" m (copyPassword ps model view)
  addItem "Add password" m (addPasswordDialog ps model)
  addItem "Delete password" m (deletePassword ps model view window)
  addItem "Change password" m (updatePasswordDialog ps model view)
  return m

-- | Copy the selected password to the clipboard, with a one minut timeout
--   until it is erased.
copyPassword :: PS.PasswordStore PS.Unlocked
             -> ListStore (ServiceName, Credentials)
             -> TreeView
             -> IO ()
copyPassword ps model view = do
  withSelectedItem model view $ \ix (s, (Credentials _ p)) -> do
    toClipboard (MSecs 60000) p

-- | Update the password list.
updatePasswords :: PS.PasswordStore PS.Unlocked
                -> ListStore (ServiceName, Credentials)
                -> IO ()
updatePasswords ps model = do
  svcnames <- PS.list ps 
  pwds <- forM svcnames $ \s -> do
    Just c <- PS.get ps s
    return (s, c)
  listStoreClear model
  forM_ (sort pwds) (listStoreAppend model)

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
      dialogRun dlg
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
  withSelectedItem model view $ \ix (s, c) -> do
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
      PS.delete ps s
      listStoreRemove model ix
    widgetDestroy dlg

-- | Create a list view containing all the accounts currently in the password
--   store.
passwordManager :: Window -> PS.PasswordStore PS.Unlocked -> IO (VBox, IO ())
passwordManager window ps = do
    svcnames <- PS.list ps 
    pwds <- forM svcnames $ \s -> do
      Just c <- PS.get ps s
      return (s, c)
    lst <- listStoreNew (sort pwds)
    r <- cellRendererTextNew
    
    services <- treeViewColumnNew
    cellLayoutPackStart services r False
    cellLayoutSetAttributes services r lst $
      \(s, _) -> [cellText := show s]
    treeViewColumnSetTitle services "Service"
    treeViewColumnSetMinWidth services 200
  
    names <- treeViewColumnNew
    cellLayoutPackStart names r False
    cellLayoutSetAttributes names r lst $
      \(_, c) -> [cellText := showName c]
    treeViewColumnSetTitle names "Username"
    treeViewColumnSetMinWidth names 200
  
    strength <- treeViewColumnNew
    cellLayoutPackStart strength r False
    cellLayoutSetAttributes strength r lst $
      \(_, c) -> [cellText := if hasPassword c
                                then show (judge $ analyze c)
                                else "No password!"]
    treeViewColumnSetTitle strength "Password Strength"
    treeViewColumnSetMinWidth strength 100

    pwdlist <- treeViewNewWithModel lst
    treeViewAppendColumn pwdlist services
    treeViewAppendColumn pwdlist names
    treeViewAppendColumn pwdlist strength
    vbox <- vBoxNew False 5
    containerAdd vbox pwdlist
    set vbox [boxChildPacking pwdlist := PackGrow]

    ctxmenu <- contextMenu ps lst pwdlist window
    pwdlist `on` buttonPressEvent $ do
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
  dialogAddButton dlg "Cancel" ResponseReject
  dialogAddButton dlg "Add account" ResponseAccept

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
      PS.add ps (fromString svc) (Credentials (fromString user) (fromString pass))
      updatePasswords ps model
    ResponseReject -> do
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
    dialogAddButton dlg "Cancel" ResponseReject
    dialogAddButton dlg "Update password" ResponseAccept

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
        PS.update ps (fromString svc) (const $ Credentials (fromString user) (fromString pass))
        updatePasswords ps model
      ResponseReject -> do
        return ()
    widgetDestroy dlg
