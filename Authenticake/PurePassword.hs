{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE FlexibleContexts #-}

module Authenticake.PurePassword (

    PurePassword
  , emptyPurePassword
  , fromMap

  , PurePasswordNotAuthentic(..)

  ) where

import qualified Data.Text as T
import qualified Data.Map as M
import Control.Applicative
import Data.Functor.Identity
import Authenticake.Authenticate

-- | In-memory authenticator based on secret keys. If you give the value of
--   the map at the subject point, then you're authenticated.
data PurePassword = PurePassword (M.Map T.Text T.Text)

-- | Can never fail for exceptional reasons, unlike an I/O based authenticator.
data PurePasswordNotAuthentic
  = SubjectNotFound
  | ChallengeMismatch
  deriving (Show)

instance Authenticator PurePassword where
  type NotAuthenticReason PurePassword s = PurePasswordNotAuthentic
  type Subject PurePassword t = T.Text
  type Challenge PurePassword s = T.Text
  type AuthenticatorF PurePassword = Identity
  authenticate (PurePassword map) proxy key value = case M.lookup key map of
    Just value' -> if value == value'
                   then return Nothing
                   else return $ Just ChallengeMismatch
    Nothing -> return $ Just SubjectNotFound

emptyPurePassword :: PurePassword
emptyPurePassword = PurePassword M.empty

fromMap :: M.Map T.Text T.Text -> PurePassword
fromMap = PurePassword

setPassword :: T.Text -> Maybe T.Text -> PurePassword -> PurePassword
setPassword subject challenge (PurePassword map) = PurePassword (M.alter (const challenge) subject map)
