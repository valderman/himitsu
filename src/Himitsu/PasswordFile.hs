{-# LANGUAGE GADTs, FlexibleInstances, OverloadedStrings #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}
-- | A file representing a complete, encrypted password database with
--   additional metadata.
module Himitsu.PasswordFile (
    ProtectedFile (..), PasswordFile, ServiceName, Secret, Accounts,
    encryptPF, decryptPF, newPF
  ) where
import Control.Monad
import Control.Applicative
import qualified Data.ByteString.Lazy.Char8 as BSL
import qualified Data.ByteString as BS
import Data.ByteString.Base64.Lazy as B64
import Data.Text hiding (map)
import Data.Text.Encoding
import Data.Aeson hiding (encode, decode)
import qualified Data.Aeson as Aeson (encode, decode)
import Crypto.Threefish.Skein.StreamCipher
import qualified Crypto.Threefish.Random as R
import Crypto.Threefish.Skein
import Crypto.Threefish
import Crypto.Scrypt
import Himitsu.Credentials
import Himitsu.Crypto
import Himitsu.SortedList
import qualified Data.Vector as V (toList, fromList)
import Data.String
import Data.IORef
import System.IO.Unsafe

{-# NOINLINE prng #-}
prng :: IORef R.SkeinGen
prng = unsafePerformIO $ R.newSkeinGen >>= newIORef

randomVal :: R.Random a => (a, a) -> IO a
randomVal r = do
  atomicModifyIORef' prng (\g -> case R.randomR r g of (a, b) -> (b, a))

randomBytes :: Int -> IO BS.ByteString
randomBytes n = do
  atomicModifyIORef' prng (\g -> case R.randomBytes n g of (a, b) -> (b, a))

newtype ServiceName = ServiceName Text deriving (Ord, Eq)

instance Show ServiceName where
  show (ServiceName sn) = unpack sn

instance ToJSON ServiceName where
  toJSON (ServiceName sn) = toJSON sn

instance FromJSON ServiceName where
  parseJSON j = ServiceName <$> parseJSON j

instance IsString ServiceName where
  fromString = ServiceName . pack

instance ToJSON (Secret Locked a) where
  toJSON (Locked x) = String $! decodeUtf8 . BSL.toStrict $ B64.encode x

instance FromJSON (Secret Locked a) where
  parseJSON (String s) =
    case B64.decode $ BSL.fromStrict $ encodeUtf8 s of
      Right x -> return $ Locked x
      _       -> mzero
  parseJSON _ =
    mzero

instance FromJSON Key256 where
  parseJSON (String k) = do
    liftMaybe . readHex $ unpack k
  parseJSON _ =
    mzero

instance FromJSON KeyParams where
  parseJSON (Object o) =
    KeyParams <$> o .: "logN" <*> o .: "r" <*> o .: "p"
  parseJSON _ =
    mzero

instance ToJSON KeyParams where
  toJSON (KeyParams logN r p) = object ["logN" .= toJSON logN,
                                        "r" .= toJSON r,
                                        "p" .= toJSON p]
instance ToJSON Key256 where
  toJSON = toJSON . show

instance FromJSON [(ServiceName, Credentials)] where
  parseJSON (Array arr) = forM (V.toList arr) $ \x -> do
    case x of
      Object o -> do
        sn <- o .: "service"
        c <- o .: "credentials"
        return (sn, c)
      _ ->
        mzero
  parseJSON _ =
    mzero

instance ToJSON [(ServiceName, Credentials)] where
  toJSON = Array . V.fromList . map f
    where f (sn, c) = object ["service" .= sn, "credentials" .= c]

instance ToJSON Accounts where
  toJSON = toJSON . toList

instance FromJSON Accounts where
  parseJSON x = fromList <$> parseJSON x

instance FromJSON Credentials where
  parseJSON (Object o) =
    Credentials <$> (fromString <$> o .: "username")
                <*> (fromString <$> o .: "password")
  parseJSON _ =
    mzero

instance ToJSON Credentials where
  toJSON (Credentials username password) =
    object ["username" .= toJSON (show username),
            "password" .= toJSON (show password)]

-- | Data structure representing a JSON file containing encrypted content.
data ProtectedFile a b = ProtectedFile {
    pfRevision   :: !Int,         -- ^ The file version. Increase on save.
    pfMac        :: !Block256,    -- ^ Skein-MAC of pfRevision|pfSecret.
    pfSecret     :: !(Secret a b),-- ^ The secret stored in the file; encrypted
                                  --   or decrypted.
    pfSalt       :: !Salt,        -- ^ Salt for key derivation.
    pfNonce      :: !Key256,      -- ^ Nonce for the encryption.
    pfKeyParams  :: !KeyParams    -- ^ Key derivation parameters.
  } deriving (Eq)

type Accounts = SortedList (ServiceName, Credentials)
type PasswordFile a = ProtectedFile a Accounts

instance ToJSON Salt where
  toJSON (Salt s) = toJSON . B64.encode $ BSL.fromStrict s

instance FromJSON Salt where
  parseJSON (String s) = do
    s' <- liftEither . B64.decode . BSL.fromStrict $ encodeUtf8 s
    return . Salt $ BSL.toStrict s'
  parseJSON _ =
    mzero

instance ToJSON a => ToJSON (ProtectedFile Locked a) where
  toJSON pf = object [
        ("revision", toJSON $ pfRevision pf),
        ("mac", toJSON $ pfMac pf),
        ("secret", toJSON $ pfSecret pf),
        ("salt", toJSON $ pfSalt pf),
        ("nonce", toJSON $ pfNonce pf),
        ("keyParams", toJSON $ pfKeyParams pf)
      ]

instance FromJSON (ProtectedFile Locked a) where
  parseJSON (Object o) =
    ProtectedFile <$> o .: "revision"
                  <*> o .: "mac"
                  <*> o .: "secret"
                  <*> o .: "salt"
                  <*> o .: "nonce"
                  <*> o .: "keyParams"
  parseJSON _ =
    mzero

liftMaybe :: Monad m => Maybe a -> m a
liftMaybe (Just x) = return x
liftMaybe _        = fail "liftMaybe got a Nothing!"

liftEither :: (Monad m, Show a) => Either a b -> m b
liftEither (Right x) = return x
liftEither (Left e)  = fail $ "liftEither got a Left: " ++ show e

-- | Verify the integrity of and decrypt a password file.
decryptPF :: FromJSON a
          => ProtectedFile Locked a
          -> Password
          -> Maybe (ProtectedFile Unlocked a)
decryptPF pf pwd = do
  k <- kKey <$> deriveKey (pfKeyParams pf) (pfSalt pf) pwd
  checkMac k
  secret <- Aeson.decode $ decrypt k (pfNonce pf) (fromLocked $ pfSecret pf)
  return $ ProtectedFile {
      pfRevision = pfRevision pf,
      pfMac = pfMac pf,
      pfSecret = Unlocked secret,
      pfSalt = pfSalt pf,
      pfKeyParams = pfKeyParams pf,
      pfNonce = pfNonce pf
    }
  where
    rev = BSL.pack $ show $ pfRevision pf
    mac' k = skeinMAC k $ rev `BSL.append` (fromLocked $ pfSecret pf)
    checkMac k
      | mac' k == pfMac pf = return ()
      | otherwise          = Nothing

-- | Encrypt-then-MAC a protected file.
encryptPF :: ToJSON a
          => ProtectedFile Unlocked a
          -> Password
          -> IO (ProtectedFile Locked a)
encryptPF pf pwd = do
    saltlen <- randomVal (5, 10)
    salt <- Salt <$> randomBytes saltlen
    Just nonce <- toBlock <$> randomBytes 32 -- never fails for 32 bytes
    let Just k = deriveKey (pfKeyParams pf) salt pwd
        key = kKey k
        cryptotext = encrypt key nonce plaintext
        revision = pfRevision pf -- File hasn't necessarily changed
        mac = skeinMAC key $ BSL.pack (show revision) `BSL.append` cryptotext
    return $! ProtectedFile {
        pfRevision = revision,
        pfMac = mac,
        pfSecret = Locked cryptotext,
        pfSalt = salt,
        pfKeyParams = pfKeyParams pf,
        pfNonce = nonce
      }
  where
    plaintext = Aeson.encode . fromUnlocked $ pfSecret pf

instance Functor (ProtectedFile Unlocked) where
  fmap f pf = pf {pfSecret = fmap f $ pfSecret pf}

newPF :: b -> IO (ProtectedFile Unlocked b)
newPF x = do
  let Just zeroes = readHex $ Prelude.replicate 64 '0'
  return $ ProtectedFile {
      pfRevision = 0,
      pfMac = zeroes,
      pfSecret = Unlocked x,
      pfSalt = Salt "",
      pfNonce = zeroes,
      pfKeyParams = defaultKeyParams
    }
