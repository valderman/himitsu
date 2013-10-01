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
  toKey = fromJust . deriveKey defaultKeyParams globalSalt
  -- | Generate a key from a secret using custom Scrypt settings and salt.
  deriveKey :: KeyParams -> BS.ByteString -> a -> Maybe Key

instance Secret Key where
  toKey = id
  deriveKey _ _ = Just

instance Secret Text where
  deriveKey params salt pass = deriveKey params salt (encodeUtf8 pass)

instance Secret BS.ByteString where
  deriveKey (n, r, p) saltBytes pass = do
      ps <- scryptParams (fromIntegral n) (fromIntegral r) (fromIntegral p)
      return $! Key n r p saltBytes (key ps)
    where
      salt = Salt saltBytes
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
--   The salt must not be longer than 255 bytes.
data Key = Key {
    kN    :: !Word8, -- ^ Scrypt N parameter
    kR    :: !Word8, -- ^ Scrypt r parameter
    kP    :: !Word8, -- ^ Scrypt p parameter
    kSalt :: !BS.ByteString,
    kKey  :: !TF.Key256
  }

-- | Scrypt N, r and p parameters.
type KeyParams = (Word8, Word8, Word8)

-- | Extract the key parameters from a message.
msgKeyParams :: BSL.ByteString -> Maybe (Word8, Word8, Word8)
msgKeyParams msg =
    case scryptParams (fromIntegral n) (fromIntegral r) (fromIntegral p) of
      Just _ -> Just (n, r, p)
      _      -> Nothing
  where
    len = fromIntegral $ BSL.head msg
    [n, r, p] = BSL.unpack $ BSL.take 3 $ BSL.drop (len+1) msg

-- | Extract the key parameters from a message.
msgSalt :: BSL.ByteString -> BS.ByteString
msgSalt msg =
    BSL.toStrict $ BSL.take (fromIntegral len) $ BSL.tail msg
  where
    len = BSL.head msg

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
defaultKeyParams = (17, 8, 1)

-- | Encrypt-then-MAC a message, then prepend the parameters used to generate
--   the key.
encrypt :: Key -> BSL.ByteString -> BSL.ByteString
encrypt (Key n r p s k) plaintext =
    BSL.concat [salt, BSL.pack [n,r,p], TF.encryptBytes k plaintext]
  where
    salt = runPutLazy $ do
      putWord8 $ fromIntegral $ BS.length s
      putByteString s

-- | Verify and decrypt a message.
decrypt :: Key -> BSL.ByteString -> Maybe BSL.ByteString
decrypt (Key _ _ _ _ k) msg =
    case TF.decryptBytes k (BSL.drop (saltlen+4) msg) of
      Right x -> Just x
      _       -> Nothing
  where
    saltlen = fromIntegral $ BSL.head msg
