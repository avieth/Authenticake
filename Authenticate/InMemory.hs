{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE FlexibleContexts #-}

module Authenticate.InMemory (

    InMemory
  , emptyInMemory
  , populateInMemory

  , InMemoryFailure
  , InMemoryUpdateFailure

  ) where

import qualified Data.Text as T
import qualified Data.Map as M
import Control.Applicative
import Control.RichConditional
import Authenticate.Authenticate

-- | In-memory authenticator.
--   Demands reads and writes in a safe, controlled way.
data InMemory = InMemory (M.Map T.Text T.Text)

-- | Can never fail for exceptional reasons, unlike an I/O based authenticator.
data InMemoryFailure
  = UsernameNotFound
  | InvalidPassword
  deriving (Show)

-- | Can never fail!
data InMemoryUpdateFailure

instance Authenticator InMemory where
  type Failure InMemory = InMemoryFailure
  type Subject InMemory t = T.Text
  type Challenge InMemory t = T.Text
  authenticatorDecision (InMemory map) _ key value = case M.lookup key map of
    Just value' -> if value == value' then return Nothing else return $ Just InvalidPassword
    Nothing -> return $ Just UsernameNotFound

instance MutableAuthenticator InMemory where
  type UpdateFailure InMemory = InMemoryUpdateFailure
  authenticatorUpdate (InMemory map) _ key value =
    Right . InMemory <$> pure (M.insert key value map)

instance AuthenticationContext InMemory where
  type AuthenticatingAgent InMemory = InMemory
  authenticatingAgent = id

emptyInMemory :: InMemory
emptyInMemory = InMemory M.empty

populateInMemory
  :: Authenticatable InMemory t
  => [(t, Challenge InMemory t)]
  -> InMemory
  -> IO InMemory
populateInMemory [] inmem = return inmem
populateInMemory (x : xs) inmem = do
  result <- setAuthentication inmem (fst x) (snd x)
  ifElse
    result
    (\inmem' -> populateInMemory xs inmem')
    (\failure -> populateInMemory xs inmem)
