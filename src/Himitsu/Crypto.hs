{-# LANGUAGE OverloadedStrings, GADTs, FlexibleInstances #-}
module Himitsu.Crypto where
import Crypto.Scrypt
import qualified Crypto.Threefish as TF
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BSL
import Data.Word (Word8)
import Data.Maybe (fromJust)
import Data.Text (Text)
import Data.Text.Encoding (encodeUtf8)
import Data.Int (Int64)

-- | Any type that may be used to generate a key.
class KeyLike a where
  -- | Generate a key from a secret using the default Scrypt settings.
  toKey :: a -> Key
  toKey = fromJust . deriveKey defaultKeyParams globalSalt
  -- | Generate a key from a secret using custom Scrypt settings and salt.
  deriveKey :: KeyParams -> Salt -> a -> Maybe Key

instance KeyLike Key where
  toKey = id
  deriveKey _ _ = Just

instance KeyLike Text where
  deriveKey params salt pass = deriveKey params salt (encodeUtf8 pass)

instance KeyLike BS.ByteString where
  deriveKey (KeyParams n r p) salt pass = do
      ps <- scryptParams (fromIntegral n) (fromIntegral r) (fromIntegral p)
      return $! Key n r p salt (key ps)
    where
      -- 256 bit key; pad to 32 bits
      key ps = fromJust
             . TF.toBlock
             . padKey 32
             . getHash
             . scrypt ps salt
             $ Pass pass

globalSalt :: Salt
globalSalt = Salt "\"$€][)EAR¢]®ß"

-- | Describes a key with its derivation parameters.
--   The memory use of the key derivation function is about 128*r*N^2,
--   and run time can be tuned separately from memory use with the p parameter.
--   The salt must not be longer than 255 bytes.
data Key = Key {
    kN    :: !Word8, -- ^ Scrypt log N parameter
    kR    :: !Word8, -- ^ Scrypt r parameter
    kP    :: !Word8, -- ^ Scrypt p parameter
    kSalt :: !Salt,
    kKey  :: !TF.Key256
  }

-- | Key parameters for scrypt key derivation.
data KeyParams = KeyParams {
    kpLogN :: Word8,
    kpR    :: Word8,
    kpP    :: Word8
  } deriving (Eq)

-- | Pad a ByteString to n bytes. If the given ByteString is empty,
--   the resulting key will be composed by n null bytes. If it is non-empty
--   but shorter than n bytes, the key will be replicated up to n bytes.
--   If it is longer, the key will consist of the first n bytes of the input.
padKey :: Int64 -> BS.ByteString -> BS.ByteString
padKey sz "" =
    BS.replicate (fromIntegral sz) 0
padKey sz bs =
    BS.concat
     . BSL.toChunks
     . BSL.take sz
     . BSL.fromChunks 
     $ replicate (fromIntegral $ sz `div` len + 1) bs
  where
    len = fromIntegral $ BS.length bs

-- | Default key parameters: use 128MB of memory and take about 0.3 seconds
--   on a mobile Ivy Bridge Core i5.
defaultKeyParams :: KeyParams
defaultKeyParams = KeyParams 17 8 1

data Locked
data Unlocked

fromLocked :: Secret Locked a -> BSL.ByteString
fromLocked (Locked x) = x

fromUnlocked :: Secret Unlocked a -> a
fromUnlocked (Unlocked x) = x

-- | Any piece of data that may be either in an encrypted or a decrypted state.
data Secret e a where
  Locked   :: BSL.ByteString -> Secret Locked a
  Unlocked :: a -> Secret Unlocked a

instance Eq a => Eq (Secret e a) where
  (Locked a)   == (Locked b)   = a == b
  (Unlocked a) == (Unlocked b) = a == b
  _            == _            = error "This can't happen due to type safety."

instance Functor (Secret Unlocked) where
  fmap f (Unlocked x) = Unlocked (f x)
