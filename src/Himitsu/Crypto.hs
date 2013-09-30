{-# LANGUAGE OverloadedStrings #-}
module Himitsu.Crypto where
import Crypto.Scrypt
import qualified Crypto.Threefish.Authenticated as TF
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BSL
import Data.Word (Word8)
import Data.Maybe (fromJust)
import Data.Text (Text)
import Data.Text.Encoding (encodeUtf8)
import Data.Serialize (encode, decode)
import Data.Int (Int64)
import Data.Serialize

-- | Any type that may be used to generate a key.
class Secret a where
  -- | Generate a key from a secret using the default Scrypt settings.
  toKey :: a -> Key
  toKey = fromJust . deriveKey defaultKeyParams
  -- | Generate a key from a secret using custom Scrypt settings.
  deriveKey :: KeyParams -> a -> Maybe Key

instance Secret Key where
  toKey = id
  deriveKey = const Just

instance Secret Text where
  deriveKey params pass = deriveKey params (encodeUtf8 pass)

instance Secret BS.ByteString where
  deriveKey (n, r, p) pass = do
      ps <- scryptParams (fromIntegral n) (fromIntegral r) (fromIntegral p)
      return $! Key n r p (key ps)
    where
      salt = Salt globalSalt
      -- 256 bit key; pad to 32 bits
      key ps = fromJust
             . TF.toBlock
             . padKey 32
             . unHash
             . scrypt ps salt
             $ Pass pass

globalSalt :: BS.ByteString
globalSalt = "\"$€][)EAR¢]®ß"

-- | Describes a key with its derivation parameters.
--   The memory use of the key derivation function is about 128*r*N^2,
--   and run time can be tuned separately from memory use with the p parameter.
data Key = Key {
    kN   :: !Word8, -- ^ Scrypt N parameter
    kR   :: !Word8, -- ^ Scrypt r parameter
    kP   :: !Word8, -- ^ Scrypt p parameter
    kKey :: !TF.Key256
  }

-- | An encrypted message.
data Message = Message (Word8, Word8, Word8) BSL.ByteString

instance Serialize Message where
  put (Message (n, r, p) cryptotext) = do
    putWord8 n >> putWord8 r >> putWord8 p
    putWord64le (fromIntegral $ BSL.length cryptotext)
    putLazyByteString cryptotext
  get = do
    n <- getWord8 ; r <- getWord8 ; p <- getWord8
    len <- getWord64le
    cryptotext <- getLazyByteString (fromIntegral len)
    return $! Message (n, r, p) cryptotext

-- | Scrypt N, r and p parameters.
type KeyParams = (Word8, Word8, Word8)

-- | Extract the key parameters from a message.
msgKeyParams :: BSL.ByteString -> Maybe (Word8, Word8, Word8)
msgKeyParams msg =
    case scryptParams (fromIntegral n) (fromIntegral r) (fromIntegral p) of
      Just _ -> Just (n, r, p)
      _      -> Nothing
  where
    [n, r, p] = BSL.unpack $ BSL.take 3 msg

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

-- | Default key parameters: use 64MB of memory and take about 0.2 seconds
--   on a mobile Ivy Bridge Core i5.
defaultKeyParams :: KeyParams
defaultKeyParams = (16, 8, 1)

-- | Encrypt-then-MAC a message, then prepend the parameters used to generate
--   the key.
encrypt :: Key -> BSL.ByteString -> BSL.ByteString
encrypt (Key n r p k) plaintext =
    BSL.append (BSL.pack [n,r,p]) (TF.encryptBytes k plaintext)

-- | Verify and decrypt a message.
decrypt :: Key -> BSL.ByteString -> Maybe BSL.ByteString
decrypt (Key _ _ _ k) msg =
  case TF.decryptBytes k (BSL.drop 3 msg) of
    Right x -> Just x
    _       -> Nothing
