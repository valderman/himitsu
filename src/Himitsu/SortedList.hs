module Himitsu.SortedList (
    SortedList,
    deleteAt, updateAt, getAt, insert, fromList, mapSort, withSorted, toList,
    empty, singleton, Himitsu.SortedList.length, Himitsu.SortedList.null
  ) where
import qualified Data.List as List (sort, insert, splitAt)

-- | A sorted list.
newtype SortedList a = Sorted [a]

-- | Delete an item from an account list.
deleteAt :: Int -> SortedList a -> SortedList a
deleteAt n (Sorted xs) = Sorted $ front ++ tail back
  where (front, back) = List.splitAt n xs

-- | Update an entry in an account list.
updateAt :: Ord a => Int -> (a -> a) -> SortedList a -> SortedList a
updateAt n f (Sorted xs) =
    Sorted $ case List.splitAt n xs of
               (front, x:back) -> List.insert (f x) (front ++ back)
               _               -> xs

-- | Fetch an entry from an account list.
getAt :: Int -> SortedList a -> Maybe a
getAt n (Sorted xs) =
  case drop n xs of
    (x:_) -> Just x
    _     -> Nothing

-- | Insert an item into an account list.
insert :: Ord a => a -> SortedList a -> SortedList a
insert x (Sorted xs) = Sorted $ List.insert x xs

-- | Create a sorted list from a list.
fromList :: Ord a => [a] -> SortedList a
fromList = Sorted . List.sort

-- | Extract the sorted list.
toList :: SortedList a -> [a]
toList (Sorted xs) = xs

-- | Map a function over the given sorted list, then sort it.
mapSort :: Ord b => (a -> b) -> SortedList a -> SortedList b
mapSort f = withSorted (map f)

-- | Perform a list computation over a sorted list, then sort it.
withSorted :: Ord b => ([a] -> [b]) -> SortedList a -> SortedList b
withSorted f = Sorted . List.sort . f . toList

-- | An empty, and thus sorted, list.
empty :: SortedList a
empty = Sorted []

-- | A sorted list with one element.
singleton :: a -> SortedList a
singleton x = Sorted [x]

-- | Get the length of a sorted list.
length :: SortedList a -> Int
length = Prelude.length . toList

-- | Is the given sorted list empty?
null :: SortedList a -> Bool
null = Prelude.null . toList
