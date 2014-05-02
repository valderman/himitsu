module PasswordGenerator (newPasswordBox) where
import Graphics.UI.Gtk
import Crypto.Threefish.Random
import Data.IORef
import System.IO.Unsafe
import Graphics.Rendering.Pango.Font
import Himitsu.PasswordUtils
import PasswordDialogs (passwordBox)

{-# NOINLINE prng #-}
prng :: IORef SkeinGen
prng = unsafePerformIO $ newSkeinGen >>= newIORef

-- | Returns a HBox containing everything needed to add or modify an account,
--   along with references to entry boxes containing the account's service
--   name, account name and password respectively.
newPasswordBox :: Dialog -> IO (HBox, Entry, Entry, Entry)
newPasswordBox dlg = do
  box <- hBoxNew False 10
  (pass, passframe, passent) <- generatorBox dlg
  (account, serviceent, userent) <- accountBox passframe dlg
  containerAdd box account
  containerAdd box pass
  return (box, serviceent, userent, passent)

-- | Returns a VBox containing inputs for entering account details, an entry
--   box which will contain a service name, and an entry box which will contain
--   an account name for that service.
accountBox :: Frame -> Dialog -> IO (VBox, Entry, Entry)
accountBox passframe dlg = do
  vbox <- vBoxNew False 10
  containerSetBorderWidth vbox 5
  accountframe <- frameNew
  frameSetLabel accountframe "Account Details"
  accountbox <- vBoxNew False 5
  containerSetBorderWidth accountbox 5
  containerAdd accountframe accountbox
  containerAdd vbox accountframe
  
  -- Service name
  servicelabel <- labelNew (Just "Name of service/website")
  serviceent <- entryNew
  _ <- serviceent `on` entryActivate $ dialogResponse dlg ResponseAccept
  servicelblalign <- alignmentNew 0 0 0 0
  containerAdd servicelblalign servicelabel
  containerAdd accountbox servicelblalign
  containerAdd accountbox serviceent
  
  -- Username for service
  userlabel <- labelNew (Just "Your username")
  userent <- entryNew
  _ <- userent `on` entryActivate $ dialogResponse dlg ResponseAccept
  userlblalign <- alignmentNew 0 0 0 0
  containerAdd userlblalign userlabel
  containerAdd accountbox userlblalign
  containerAdd accountbox userent

  containerAdd vbox passframe

  set vbox [boxChildPacking passframe := PackNatural,
            boxChildPacking accountframe := PackNatural]
  return (vbox, serviceent, userent)

-- | Returns a framed box containing settings for password generation, a framed
--   box containing a password entry field with a "generate" button, and the
--   password entry field itself.
generatorBox :: Dialog -> IO (Frame, Frame, Entry)
generatorBox dlg = do
  frame <- frameNew
  containerSetBorderWidth frame 5
  frameSetLabel frame "Generator Settings"
  box <- vBoxNew False 10
  containerSetBorderWidth box 5
  containerAdd frame box

  -- What chars should go in the password?
  includeframe <- frameNew
  frameSetLabel includeframe "Password Characters"
  includebox <- vBoxNew False 5
  containerSetBorderWidth includebox 5
  lower <- checkButtonNewWithLabel "Include lowercase letters"
  upper <- checkButtonNewWithLabel "Include uppercase letters"
  numbers <- checkButtonNewWithLabel "Include numbers"
  special <- checkButtonNewWithLabel "Include symbols"
  mapM_ (flip toggleButtonSetActive True) [lower, upper, numbers, special]
  mapM_ (containerAdd includebox) [lower, upper, numbers, special]
  containerAdd includeframe includebox
  containerAdd box includeframe

  -- How long should it be?
  lenframe <- frameNew
  frameSetLabel lenframe "Password Length"
  numcharsbox <- hBoxNew False 5
  containerSetBorderWidth numcharsbox 5
  numchars <- spinButtonNewWithRange 4 100 1
  spinButtonSetValue numchars 20
  containerAdd numcharsbox numchars
  numcharslbl <- labelNew (Just "characters")
  containerAdd numcharsbox numcharslbl
  containerAdd lenframe numcharsbox
  set numcharsbox [boxChildPacking numcharslbl := PackNatural,
                   boxChildPacking numchars := PackNatural]
  containerAdd box lenframe
    
  -- What does it look like?
  passframe <- frameNew
  frameSetLabel passframe "Your Password"
  passbox <- vBoxNew False 5
  containerSetBorderWidth passbox 5
  containerAdd passframe passbox

  -- Text box containing password.
  passent <- passwordBox dlg
  fd <- fontDescriptionNew
  fontDescriptionSetFamily fd "monospace"
  widgetModifyFont passent (Just fd)
  entrySetWidthChars passent 30
  entrySetVisibility passent False
  containerAdd passbox passent

  -- Show the password?
  visible <- checkButtonNewWithLabel "Show password"
  containerAdd passbox visible
  _ <- visible `on` toggled $ do
    toggleButtonGetActive visible >>= entrySetVisibility passent

  -- Asessing password strength
  strbox <- hBoxNew False 5
  containerSetBorderWidth strbox 5
  ratinglbl <- labelNew (Just "Password strength:")
  containerAdd strbox ratinglbl
  rating <- labelNew (Just "N/A")
  containerAdd strbox rating
  set strbox [boxChildPacking ratinglbl := PackNatural,
              boxChildPacking rating := PackNatural]
  containerAdd passbox strbox
  
  -- Set up password ratings
  let fillPW = fillNewPassword rating passent numchars lower upper numbers special
      fillPR = entryGetText passent >>= fillPasswordRating rating
  mapM_ (\x -> x `on` buttonActivated $ fillPW) [lower,upper,numbers,special]
  _ <- onValueSpinned numchars fillPW
  widgetGrabFocus passent
  _ <- passent `on` editableChanged $ fillPR

  btn <- buttonNewWithLabel "Generate"
  _ <- btn `on` buttonActivated $ do
    fillNewPassword rating passent numchars lower upper numbers special
  containerAdd passbox btn
  
  set box [boxChildPacking includeframe := PackNatural,
           boxChildPacking lenframe := PackNatural]
  return (frame, passframe, passent)
  where
    fillNewPassword r ent chars bLower bUpper bNum bSym = do
      lower <- toggleButtonGetActive bLower
      upper <- toggleButtonGetActive bUpper
      num <- toggleButtonGetActive bNum
      sym <- toggleButtonGetActive bSym
      len <- spinButtonGetValue chars
      let ps = specify (floor len) lower upper num sym
      pass <- atomicModifyIORef' prng (generate ps)
      entrySetText ent pass
      fillPasswordRating r pass

    fillPasswordRating r pass = do
      let strength = judge $ analyze pass
      labelSetText r (show strength)
