{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE FlexibleContexts #-}

module Authenticake.Pure (

    Pure
  , emptyPure
  , fromMap

  , PureFailure(..)
  , PureUpdateFailure(..)

  ) where

import qualified Data.Text as T
import qualified Data.Map as M
import Control.Applicative
import Control.RichConditional
import Authenticake.Authenticate

-- | In-memory authenticator based on secret keys. If you give the value of
--   the map at the subject point, then you're authenticated.
data Pure = Pure (M.Map T.Text T.Text)

-- | Can never fail for exceptional reasons, unlike an I/O based authenticator.
data PureFailure
  = UsernameNotFound
  | WrongSecret
  deriving (Show)

-- | Can never fail!
data PureUpdateFailure

instance Authenticator Pure where
  type Failure Pure s = PureFailure
  type Subject Pure t = T.Text
  type Challenge Pure s = T.Text
  authenticatorDecision (Pure map) _ key value = case M.lookup key map of
    Just value' -> if value == value' then return Nothing else return $ Just WrongSecret
    Nothing -> return $ Just UsernameNotFound

instance MutableAuthenticator Pure where
  type UpdateFailure Pure s = PureUpdateFailure
  authenticatorUpdate (Pure map) _ key value =
    Right . Pure <$> pure (M.insert key value map)

instance AuthenticationContext Pure where
  type AuthenticatingAgent Pure = Pure
  authenticatingAgent = id

emptyPure :: Pure
emptyPure = Pure M.empty

fromMap :: M.Map T.Text T.Text -> Pure
fromMap = Pure
