{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE FlexibleContexts #-}

module Authenticake.Password (

    Password
  , emptyPassword
  , fromMap

  , PasswordNotAuthentic(..)
  --, PasswordUpdateFailure(..)

  ) where

import qualified Data.Text as T
import qualified Data.Map as M
import Control.Applicative
import Data.Functor.Identity
import Authenticake.Authenticate

-- | In-memory authenticator based on secret keys. If you give the value of
--   the map at the subject point, then you're authenticated.
data Password = Password (M.Map T.Text T.Text)

-- | Can never fail for exceptional reasons, unlike an I/O based authenticator.
data PasswordNotAuthentic
  = SubjectNotFound
  | ChallengeMismatch
  deriving (Show)

instance Authenticator Password where
  type NotAuthenticReason Password s = PasswordNotAuthentic
  type Subject Password t = T.Text
  type Challenge Password s = T.Text
  type AuthenticatorF Password = Identity
  authenticate (Password map) proxy key value = case M.lookup key map of
    Just value' -> if value == value'
                   then return Nothing
                   else return $ Just ChallengeMismatch
    Nothing -> return $ Just SubjectNotFound

{-
-- | Can never fail!
data PasswordUpdateFailure

instance MutableAuthenticator Password where
  type UpdateFailure Password s = PasswordUpdateFailure
  authenticatorUpdate (Password map) _ key value =
    Right . Password <$> pure (M.insert key value map)

instance AuthenticationContext Password where
  type AuthenticatingAgent Password = Password
  authenticatingAgent = id
-}

emptyPassword :: Password
emptyPassword = Password M.empty

fromMap :: M.Map T.Text T.Text -> Password
fromMap = Password
