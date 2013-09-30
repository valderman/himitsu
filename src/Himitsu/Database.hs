{-# LANGUAGE GeneralizedNewtypeDeriving #-}
-- | Pure data structure for storing credentials for a variety of services.
module Himitsu.Database (
    Database, ServiceName, add, update, remove, rename, get, new, list
  ) where
import qualified Data.Map.Strict as M
import Data.String
import Data.Text
import Control.Monad
import Himitsu.Credentials
import Himitsu.Serialize

newtype ServiceName = ServiceName Text deriving (IsString, Eq, Ord)

instance Show ServiceName where
  show (ServiceName name) = unpack name

-- | A full password database.
newtype Database = Database (M.Map ServiceName Credentials)

instance SecurelyStorable ServiceName where
  put' (ServiceName sn) = put' sn
  get' = fmap ServiceName get'

instance SecurelyStorable Database where
  put' (Database db) = do
    put' $ M.size db
    mapM_ put' (M.toList db)
  get' = do
    elems <- get' :: SecGet Int
    xs <- forM [1..elems] $ const get'
    return $! Database $ M.fromList xs

-- | Add a new entry to the database. Returns Nothing if an entry by the given
--   name already exists.
add :: ServiceName -> Credentials -> Database -> Maybe Database
add k v (Database m) =
  case M.lookup k m of
    Nothing -> Just $! Database (M.insert k v m)
    _       -> Nothing

-- | Fetch a set of credentials from the database.
get :: ServiceName -> Database -> Maybe Credentials
get k (Database m) = M.lookup k m

-- | Update an entry in the database. Returns Nothing if no entry exists by the
--   given name.
update :: ServiceName
       -> (Credentials -> Credentials)
       -> Database
       -> Maybe Database
update k f (Database m) = do
  v <- M.lookup k m
  return $! Database (M.insert k (f v) m)

-- | Rename an entry.
rename :: ServiceName -> ServiceName -> Database -> Maybe Database
rename from to (Database db) = do
  v <- M.lookup from db
  return $! Database $ M.insert to v $ M.delete from db

-- | Remove an entry from the database.
remove :: ServiceName -> Database -> Database
remove k (Database m) = Database (M.delete k m)

-- | Create a new database.
new :: Database
new = Database M.empty

-- | List all services in the database.
list :: Database -> [ServiceName]
list (Database m) = M.keys m
