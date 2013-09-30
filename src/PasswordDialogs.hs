-- | Dialogs dealing with password entry.
module PasswordDialogs (requestPassword, requestNewPassword, passwordBox) where
import Graphics.UI.Gtk
import Data.String
import Himitsu.Credentials

-- | Create an entry box that stores passwords and terminates whatever dialog
--   houses it with a ResponseAccept whenever the user hits return inside it.
passwordBox :: Dialog -> IO Entry
passwordBox dlg = do
  ent <- entryNew
  ent `on` entryActivate $ dialogResponse dlg ResponseAccept
  entrySetVisibility ent False
  widgetShow ent
  return ent

-- | Dialog that prompts the user for a password. If the user selects Cancel,
--   Nothing is returned. If the users inputs a password, the provided callback
--   is used to check whether it is any good. If the callback returns Right x,
--   then requestPassword returns Just x. If the callback returns Left msg,
--   the user will be informed in red text that <msg>.
--   (Typically "wrong password" or something along those lines.)
requestPassword :: String -> (Password -> IO (Either String a)) -> IO (Maybe a)
requestPassword msg callback = do
    dlg <- dialogNew
    containerSetBorderWidth dlg 15
    dialogAddButton dlg "Cancel" ResponseReject
    dialogAddButton dlg "Unlock" ResponseAccept
    
    -- Message to user
    vbox <- dialogGetUpper dlg
    boxSetSpacing vbox 15
    lbl <- labelNew (Just msg)
    containerAdd vbox lbl
    widgetShow lbl
    
    -- Password input box
    ent <- passwordBox dlg
    containerAdd vbox ent
    
    waitForOKPass dlg lbl ent
  where
    waitForOKPass dlg lbl ent = do
      res <- dialogRun dlg
      case res of
        ResponseAccept -> do
          pass <- entryGetText ent
          res <- callback (fromString pass)
          case res of
            Right x -> do
              widgetDestroy dlg
              return (Just x)
            Left msg -> do
              labelSetText lbl msg
              entrySetText ent ""
              widgetModifyFg lbl StateNormal (Color 65535 0 0)
              waitForOKPass dlg lbl ent
        _ -> do
          widgetDestroy dlg
          return Nothing


-- | Dialog that prompts the user for a new password, and refuses to go away
--   until the user either manages to get the password right, or hits Cancel
--   in frustration.
--
--   The second argument is an optional text for a checkbox that needs to be
--   checked for the user to be able to click OK.
requestNewPassword :: String -> Maybe String -> IO (Maybe Password)
requestNewPassword msg mwarning = do
    dlg <- dialogNew
    containerSetBorderWidth dlg 15
    dialogAddButton dlg "Cancel" ResponseReject
    dialogAddButton dlg "OK" ResponseAccept
    
    -- Message to user
    vbox <- dialogGetUpper dlg
    boxSetSpacing vbox 15
    lbl <- labelNew (Just msg)
    containerAdd vbox lbl
    
    -- Warning checkbox
    warning <- case mwarning of
                 Just str -> do
                   warning <- checkButtonNewWithLabel str
                   containerAdd vbox warning
                   return (Just warning)
                 _ -> do
                   return Nothing
    
    -- Password input boxes
    pwd1 <- passwordBox dlg
    containerAdd vbox pwd1
    pwd2 <- passwordBox dlg
    containerAdd vbox pwd2
    widgetShowAll vbox
    widgetGrabFocus pwd1
    
    waitForPasswordMatch lbl warning dlg pwd1 pwd2
  where
    waitForPasswordMatch lbl warning dlg pwd1 pwd2 = do
      res <- dialogRun dlg
      case res of
        ResponseAccept -> do
          p1 <- entryGetText pwd1
          p2 <- entryGetText pwd2
          goAhead <- case warning of
            Just w -> do
              checked <- toggleButtonGetActive w
              if checked
                then return True
                else do
                  let msgText = "Please check the box to indicate that you " ++
                                "really know what you are doing!"
                  dlg <- messageDialogNew Nothing
                                          [DialogModal]
                                          MessageWarning
                                          ButtonsOk
                                          msgText
                  dialogRun dlg
                  widgetDestroy dlg
                  return False
            _ -> do
              return True
          if goAhead
            then do
              if p1 /= p2
                then do
                  labelSetText lbl $ "The passwords you entered didn't " ++
                                     "match! Please try again."
                  widgetModifyFg lbl StateNormal (Color 65535 0 0)
                  waitForPasswordMatch lbl warning dlg pwd1 pwd2
                else do
                  widgetDestroy dlg
                  return (Just (fromString p1))
            else do
              waitForPasswordMatch lbl warning dlg pwd1 pwd2
        _ -> do
          widgetDestroy dlg
          return Nothing
