{-# LANGUAGE TypeSynonymInstances, FlexibleInstances #-}
-- | Utilities for generating and evaluating passwords.
module Himitsu.PasswordUtils (
    PasswordSpec, Strength (..), ApproxTime (..), PasswordLike (..),
    specify, generate, judge, entropyFor, timeToBreak
  ) where
import System.Random
import Data.Char

-- | Highly subjective measurement of password strength.
data Strength =
  Useless | Weak | VeryWeak | Medium | Strong | VeryStrong | Awesome
  deriving (Ord, Eq, Enum)

instance Show Strength where
  show Useless    = "Useless!"
  show VeryWeak   = "Very weak"
  show Weak       = "Weak"
  show Medium     = "So-so"
  show Strong     = "Strong!"
  show VeryStrong = "Very strong!"
  show Awesome    = "AWESOME!"

-- | Approximation of time scales. Instant is defined as less than a second,
--   and forever is defined as well beyond the heat death of the universe.
data ApproxTime =
  Instant | Seconds | Minutes | Hours | Days | Weeks | Months | Years |
  Decades | Centuries | Millennia | MYears | GYears | Forever
  deriving (Ord, Eq, Enum)

instance Show ApproxTime where
  show Instant   = "Instant"
  show Seconds   = "Seconds"
  show Minutes   = "Minutes"
  show Hours     = "Hours"
  show Days      = "Days"
  show Weeks     = "Weeks"
  show Months    = "Months"
  show Years     = "Years"
  show Decades   = "Decades"
  show Centuries = "Centuries"
  show Millennia = "Thousands of years"
  show MYears    = "Millions of years"
  show GYears    = "Billions of years"
  show Forever   = "Forever"

-- | Specification of a password, including length and included character
--   classes. Currently only supports the printable ASCII subset.
data PasswordSpec = PasswordSpec {
    psLength  :: Int,
    psLCase   :: Bool,
    psUCase   :: Bool,
    psNumbers :: Bool,
    psSymbols :: Bool
  }

-- | Create a password specification from length, lowercase, uppercase, numeric
--   and symbol chars.
specify :: Int -> Bool -> Bool -> Bool -> Bool -> PasswordSpec
specify = PasswordSpec

-- | Any type that may be analyzed as a password.
class PasswordLike a where
  analyze :: a -> PasswordSpec

instance PasswordLike String where
  analyze pwd = PasswordSpec {
    psLength  = length pwd,
    psLCase   = any isLower pwd,
    psUCase   = any isUpper pwd,
    psNumbers = any isDigit pwd,
    psSymbols = any (flip elem asciiSyms) pwd
  }

-- | Highly subjectively determine the strength of a password.
--   In general, Useless and VeryWeak passwords are at risk even from the most
--   casual script kiddie doing online attacks. Weak passwords are OK as long
--   against online attacks (standing up to at least a decade of brute forcing
--   at 1000 guesses per second) but will fail quickly against any offline
--   attack.
--
--   Passwords considered Strong and VeryStrong will stand up to most any
--   offline attack, and Awesome passwords are unbreakable even in theory.
judge :: PasswordSpec -> Strength
judge ps =
  case (timeToBreak 1000 ps, timeToBreak 1000000000 ps) of
    (ttb1K, ttb1G) | ttb1G >= Forever   -> Awesome
                   | ttb1G >= MYears    -> VeryStrong
                   | ttb1G >= Millennia -> Strong
                   | ttb1G >= Years     -> Medium
                   | ttb1K >= Decades   -> Weak
                   | ttb1K >= Weeks     -> VeryWeak
                   | otherwise          -> Useless

-- | How many bits of entropy do we have in a password generated from the given
--   spec?
entropyFor :: PasswordSpec -> Double
entropyFor (PasswordSpec len lc uc ns ss) =
  logBase 2 . fromIntegral . (^len) $ sum [if lc then 26 else 0,
                                           if uc then 26 else 0,
                                           if ns then 10 else 0,
                                           if ss then 33 else 0 :: Integer]

-- | How long time would it take, on average, to brute force a password
--   generated from the given specification at n guesses per second?
timeToBreak :: Int -> PasswordSpec -> ApproxTime
timeToBreak gps ps =
    case (2**entropyFor ps)/(2*fromIntegral gps) of
      t | t < 1              -> Instant
        | t < 60             -> Seconds
        | t < 3600           -> Minutes
        | t < oneDay         -> Hours
        | t < oneDay*7       -> Days
        | t < oneDay*31      -> Weeks
        | t < oneDay*365     -> Months
        | t < oneYear*100    -> Years
        | t < oneKYears      -> Centuries
        | t < oneMYears      -> Millennia
        | t < oneGYears      -> MYears
        | t < 1000*oneGYears -> GYears
        | otherwise          -> Forever
  where
    oneDay = 3600*24
    oneYear = 365*oneDay
    oneKYears = 1000*oneYear
    oneMYears = 1000*oneKYears
    oneGYears = 1000*oneMYears

-- | Printable ASCII non-alphanumeric characters, sans space.
asciiSyms :: String
asciiSyms = "!\"#¤%&/()=?`@${[]}\\+^~'*<>|,;.:-_"

-- | Generate a password from a specification.
generate :: RandomGen g => PasswordSpec -> g -> (g, String)
generate (PasswordSpec len lower upper num sym) g =
    if null cs then (g, "") else go len "" g
  where
    cs = concat [
        if lower then ['a'..'z'] else [],
        if upper then ['A'..'Z'] else [],
        if num   then ['0'..'9'] else [],
        if sym   then asciiSyms else []
      ]
    range = length cs
    go 0 ps gen =
      (gen, ps)
    go n ps gen =
      case randomR (0, range-1) gen of
        (ix, gen') -> go (n-1) ((cs !! ix) : ps) gen'
