{-# LANGUAGE GADTs #-}
module Himitsu.PasswordStore (
      PasswordStore, Locked, Unlocked,
      lock, unlock, save, update, get, new, add, list, open, delete, rename,
      changePass, getBackingFile, setBackingFile
  ) where
import Himitsu.Credentials
import Himitsu.Crypto hiding (Secret (..))
import Himitsu.PasswordFile
import Control.Applicative
import Control.Monad
import System.Directory
import System.FilePath
import qualified Data.ByteString.Lazy as BSL
import Control.Concurrent.MVar
import qualified Data.Aeson as Aeson
import System.IO
import qualified Himitsu.SortedList as Sorted

newtype PasswordStore a = PS (MVar Store)

data Store where
  Locked   :: !FilePath -> Store
  Unlocked :: !FilePath -> !Password -> !(PasswordFile Unlocked) -> Store

-- | Unlock the password store.
unlock :: PasswordStore Locked -> Password -> IO (Maybe (PasswordStore Unlocked))
unlock (PS r) pwd = do
    ps <- takeMVar r
    case ps of
      Locked file -> do
        mpf <- Aeson.decode <$> BSL.readFile file
        case mpf >>= flip decryptPF pwd of
          Just pf -> do
            let store = Unlocked file pwd pf
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
  (Unlocked file pwd db) <- takeMVar r
  let (dir, tmp) = splitFileName file
      db' = db {pfRevision = pfRevision db + 1}
  (tmpfile, h) <- openBinaryTempFile dir tmp
  pf <- encryptPF db' pwd
  BSL.hPut h $ Aeson.encode pf
  hClose h
  renameFile tmpfile file
  putMVar r (Unlocked file pwd db')

-- | Update a set of credentials.
update :: PasswordStore Unlocked -> Int -> Credentials -> IO Bool
update ps@(PS r) ix newcred = do
    success <- modifyMVar r update'
    when success $ save ps
    return success
  where
    update' (Unlocked f k db) = do
      case Sorted.getAt ix . fromUnlocked $ pfSecret db of
        Just _ -> do
          let upd = Sorted.updateAt ix $ \(name, _) -> (name, newcred)
          return (Unlocked f k $ fmap upd db, True)
        _ ->
          return (Unlocked f k db, False)
    update' s =
      return (s, False)

-- | Change the name of a service in a store.
rename :: PasswordStore Unlocked -> Int -> ServiceName -> IO Bool
rename ps@(PS r) ix newname = do
    success <- modifyMVar r rename'
    when success $ save ps
    return success
  where
    rename' (Unlocked f k db) = do
      case Sorted.getAt ix . fromUnlocked $ pfSecret db of
        Just _ -> do
          let upd = Sorted.updateAt ix (\(_, cred) -> (newname, cred))
          return (Unlocked f k $ fmap upd db, True)
        _ ->
          return (Unlocked f k db, False)
    rename' s =
      return (s, False)

-- | Get a set of credentials from the store.
get :: PasswordStore Unlocked -> Int -> IO (Maybe Credentials)
get (PS r) ix = do
  (Unlocked _ _ db) <- readMVar r
  return . fmap snd $ Sorted.getAt ix (fromUnlocked (pfSecret db))

-- | Create a new, unlocked password store.
new :: Password -> FilePath -> IO (PasswordStore Unlocked)
new pwd fp = do
  pf <- newPF Sorted.empty
  ps <- PS `fmap` newMVar (Unlocked fp pwd pf)
  save ps
  return ps

-- | Change the master password for the given store. The old password will no
--   longer be usable.
changePass :: PasswordStore Unlocked -> Password -> IO (PasswordStore Unlocked)
changePass ps@(PS r) pwd = do
  modifyMVar_ r $ \(Unlocked fp _ db) ->
    return (Unlocked fp pwd db)
  save ps
  return ps

-- | Add a password.
add :: PasswordStore Unlocked -> ServiceName -> Credentials -> IO ()
add ps@(PS r) name cred = do
  modifyMVar r $ \(Unlocked file key db) ->
    return (Unlocked file key $ fmap (Sorted.insert (name, cred)) db, ())
  save ps

-- | Remove a password.
delete :: PasswordStore Unlocked -> Int -> IO ()
delete ps@(PS r) ix = do
  modifyMVar_ r $ \(Unlocked file key db) ->
    return (Unlocked file key $ fmap (Sorted.deleteAt ix) db)
  save ps

-- | Return a sorted list of all credentials currently in the store.
list :: PasswordStore Unlocked -> IO [(ServiceName, Credentials)]
list (PS r) = do
  (Unlocked _ _ db) <- readMVar r
  return . Sorted.toList . fromUnlocked $ pfSecret db

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
