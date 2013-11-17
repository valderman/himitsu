{-# LANGUAGE GADTs #-}
module Himitsu.PasswordStore (
      PasswordStore, Locked, Unlocked,
      lock, unlock, save, update, get, new, add, list, open, delete, rename,
      changePass, getBackingFile, setBackingFile
  ) where
import Himitsu.Credentials
import qualified Himitsu.Database as DB
import Himitsu.Database (ServiceName)
import Himitsu.Serialize
import Himitsu.Crypto
import Control.Applicative
import Control.Monad
import System.Directory
import System.FilePath
import qualified Data.ByteString.Lazy as BSL
import Control.Concurrent.MVar
import System.IO

data Locked
data Unlocked

newtype PasswordStore a = PS (MVar Store)

data Store where
  Locked   :: !FilePath -> Store
  Unlocked :: !FilePath -> Key -> !DB.Database -> Store

-- | Unlock the password store.
unlock :: PasswordStore Locked -> Password -> IO (Maybe (PasswordStore Unlocked))
unlock (PS r) pwd = do
    ps <- takeMVar r
    case ps of
      Locked file -> do
        mdbkey <- decode' pwd <$> BSL.readFile file
        case mdbkey of
          Just (db, key) -> do
            let store = Unlocked file key db
            putMVar r store
            return (Just (PS r))
          _       -> do
            putMVar r ps
            return Nothing
      _ -> do
        putMVar r ps
        return Nothing

-- | Lock the password store.
lock :: PasswordStore Unlocked -> IO (PasswordStore Locked)
lock (PS r) = do
  modifyMVar r $ \(Unlocked file _ _) -> return (Locked file, PS r)

-- | Save an unlocked password store. The data is first written to a temporary
--   file, which then atomically replaces the old database. This ensures that
--   a power outage or other regrettable condition at the wrong time will not
--   mess up a user's database.
save :: PasswordStore Unlocked -> IO ()
save (PS r) = do
  (Unlocked file key db) <- readMVar r
  let (dir, tmp) = splitFileName file
  (tmpfile, h) <- openBinaryTempFile dir tmp
  BSL.hPut h $ encode' key db
  hClose h
  renameFile tmpfile file

-- | Update a set of credentials.
update :: PasswordStore Unlocked
       -> ServiceName
       -> (Credentials -> Credentials)
       -> IO Bool
update ps@(PS r) name f = do
    success <- modifyMVar r update'
    when success $ save ps
    return success
  where
    update' (Unlocked file k db) =
      case DB.update name f db of
        Just db' -> return (Unlocked file k db', True)
        _        -> return (Unlocked file k db, False)
    update' s =
      return (s, False)

-- | Change the name of a service in a store.
rename :: PasswordStore Unlocked -> ServiceName -> ServiceName -> IO Bool
rename ps@(PS r) from to = do
    success <- modifyMVar r rename'
    when success $ save ps
    return success
  where
    rename' (Unlocked f k db) =
      case DB.get from db of
        Just c | Just db' <- DB.add to c (DB.remove from db) ->
          return (Unlocked f k db', True)
        _ ->
          return (Unlocked f k db, False)
    rename' s =
      return (s, False)

-- | Get a set of credentials from the store.
get :: PasswordStore Unlocked -> ServiceName -> IO (Maybe Credentials)
get (PS r) name = do
  (Unlocked _ _ db) <- readMVar r
  return $! DB.get name db

-- | Create a new, unlocked password store.
new :: Password -> FilePath -> IO (PasswordStore Unlocked)
new pwd fp = do
  ps <- PS `fmap` newMVar (Unlocked fp (toKey pwd) DB.new)
  save ps
  return ps

-- | Change the master password for the given store. The old password will no
--   longer be usable.
changePass :: PasswordStore Unlocked -> Password -> IO (PasswordStore Unlocked)
changePass ps@(PS r) pwd = do
  modifyMVar_ r $ \(Unlocked fp _ db) ->
    return (Unlocked fp (toKey pwd) db)
  save ps
  return ps

-- | Add a password.
add :: PasswordStore Unlocked
    -> ServiceName
    -> Credentials
    -> IO Bool
add ps@(PS r) name cred = do
  success <- modifyMVar r $ \(Unlocked file key db) ->
    case DB.add name cred db of
      Just db' -> return (Unlocked file key db', True)
      _        -> return (undefined, False)
  when success $ save ps
  return success

-- | Remove a password.
delete :: PasswordStore Unlocked -> ServiceName -> IO ()
delete ps@(PS r) name = do
  modifyMVar_ r $ \(Unlocked file key db) ->
    return (Unlocked file key $ DB.remove name db)
  save ps

-- | Return an unsorted list of all services the database contains passwords
--   for.
list :: PasswordStore Unlocked -> IO [ServiceName]
list (PS r) = do
  (Unlocked _ _ db) <- readMVar r
  return $ DB.list db

-- | Create a new locked password store from a file. This operation only checks
--   that the file exists; it may succeed even if the password store is not
--   actually a password store at all.
open :: FilePath -> IO (Maybe (PasswordStore Locked))
open fp = do
  exists <- doesFileExist fp
  if exists
    then (Just . PS) `fmap` newMVar (Locked fp)
    else return Nothing

-- | Gets the backing file of a password store.
getBackingFile :: PasswordStore a -> IO FilePath
getBackingFile (PS r) = do
  ps <- readMVar r
  case ps of
    (Unlocked fp _ _) -> return fp
    (Locked fp)       -> return fp

-- | Sets the backing file of an unlocked password store. To do the same for
--   a locked store, just discard the old one and use @open@.
setBackingFile :: PasswordStore Unlocked -> FilePath -> IO Bool
setBackingFile (PS r) fp = do
  exists <- doesFileExist fp
  if exists
    then modifyMVar r (\(Unlocked _ k db) -> return (Unlocked fp k db, True))
    else return False
