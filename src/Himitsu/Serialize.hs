{-# LANGUAGE GeneralizedNewtypeDeriving, FlexibleInstances, 
             UndecidableInstances, OverlappingInstances #-}
-- | Handles secure serialization. We don't want to make key, passwords, etc.
--   serializable in the normal sense since that may accidentally leak data.
--   This way, sensitive data can be serialized, but only in encrypted form.
module Himitsu.Serialize (
    SecurelyStorable (..), SecGet, SecPut, SecPutM,
    encode', decode', liftPut, liftGet
  ) where
import Data.Serialize
import qualified Data.ByteString.Lazy as BSL
import Himitsu.Crypto
import Control.Applicative
import Control.Monad
import Data.Text (Text)
import Data.Text.Encoding (encodeUtf8, decodeUtf8)

newtype SecPutM a = SecPutM (PutM a) deriving (Monad, Functor, Applicative)
type SecPut = SecPutM ()
newtype SecGet a = SecGet (Get a) deriving (Monad, Functor, Applicative)

class SecurelyStorable a where
  put' :: a -> SecPut
  get' :: SecGet a

instance Serialize a => SecurelyStorable a where
  put' = SecPutM . put
  get' = SecGet $ get

instance SecurelyStorable Text where
  put' = put' . encodeUtf8
  get' = decodeUtf8 <$> get'

instance SecurelyStorable a => SecurelyStorable [a] where
  put' xs = put' (length xs) >> mapM_ put' xs
  get' = do
    len <- get' :: SecGet Int
    forM [1..len] $ const get'

instance (SecurelyStorable a, SecurelyStorable b) =>
         SecurelyStorable (a, b) where
  put' (a, b) = put' a >> put' b
  get' = get' >>= \a -> get' >>= \b -> return $! (a, b)

liftPut :: PutM a -> SecPutM a
liftPut = SecPutM

liftGet :: Get a -> SecGet a
liftGet = SecGet

runPut' :: SecPut -> BSL.ByteString
runPut' (SecPutM p) = runPutLazy p

runGet' :: SecGet a -> BSL.ByteString -> Maybe a
runGet' (SecGet g) bs =
  case runGetLazy g bs of
    Right x -> Just x
    _       -> Nothing

-- | Decrypt and decode a message encrypted by @encode'@.
decode' :: (SecurelyStorable a, Secret s)
        => s
        -> BSL.ByteString
        -> Maybe (a, Key)
decode' s m = do
  let salt = msgSalt m
  ps <- msgKeyParams m
  k <- deriveKey ps salt s
  bs <- decrypt k m
  bs' <- runGet' get' bs
  return (bs', k)

{-# NOINLINE encode' #-}
-- | Encode a securely storable value with a nonce from a high quality PRNG
--   seeded by the system's entropy pool.
encode' :: (SecurelyStorable a, Secret s) => s -> a -> BSL.ByteString
encode' s x = encrypt (toKey s) (runPut' $ put' x)
