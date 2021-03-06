{-# LANGUAGE GeneralizedNewtypeDeriving #-}
-- | Interface for handling credentials.
module Himitsu.Credentials (
    Credentials (..), Username, Password, Clipboardable (..), Timeout (..),
    mkPassword, deriveKey, hasPassword
  ) where
import Data.Text
import Data.String
import Graphics.UI.Gtk (
    clipboardGet, selectionClipboard, clipboardSetText,
    clipboardRequestText, clipboardStore, postGUIAsync
  )
import Control.Concurrent (forkIO, threadDelay)
import Himitsu.Crypto
import Himitsu.PasswordUtils

newtype Username = Username Text deriving (Eq, Ord, IsString)
newtype Password = Password Text deriving (IsString)

data Timeout = None | MSecs Int deriving (Show, Read)

instance PasswordLike Password where
  analyze (Password p) = analyze (unpack p)

instance Show Username where
  show (Username name) = unpack name

instance Show Password where
  show (Password pass) = unpack pass

-- | An entry in the database.
data Credentials = Credentials {
    entUsername :: Username, -- ^ Entry username.
    entPassword :: Password  -- ^ Entry password in clear text.
  }

instance PasswordLike Credentials where
  analyze (Credentials _ p) = analyze p

instance Eq Credentials where
  (Credentials a _) == (Credentials b _) = a == b

instance Ord Credentials where
  compare (Credentials a _) (Credentials b _) = compare a b

class Clipboardable a where
  -- | Copy the given item to the system clipboard, then erase it after the
  --   specified number of milliseconds has passed.
  toClipboard :: Timeout -> a -> IO ()

instance Clipboardable Password where
  toClipboard timeout (Password pwd) = do
    c <- clipboardGet selectionClipboard
    clipboardSetText c (unpack pwd)
    clipboardStore c
    -- If there's a timeout, clear the clipboard after it elapses, unless
    -- the clipboard contents changed in between.
    case timeout of
      MSecs ms -> do
        _ <- forkIO $ do
          threadDelay (ms*1000)
          postGUIAsync $ do
            clipboardRequestText c $ \mpwd -> do
              case mpwd of
                Just pwd' | pack pwd' == pwd -> do
                  clipboardSetText c ""
                  clipboardStore c
                _ -> do
                  return ()
        return ()
      _ ->
        return ()

instance KeyLike Password where
  deriveKey params salt (Password pwd) = deriveKey params salt pwd

-- | Do the given credentials have a non-empty password component?
hasPassword :: Credentials -> Bool
hasPassword (Credentials _ (Password p)) | Data.Text.null p = False
hasPassword _                                               = True

-- | Create a password from a Text.
mkPassword :: Text -> Password
mkPassword = Password
