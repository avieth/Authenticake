{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE MultiParamTypeClasses #-}

module Authenticake.Strict (

    Strict(..)
  , StrictDenial

  ) where

import Authenticake.Authenticate

-- | The StrictAuthenticator never authenticates anybody.
--   If Authenticator instances form a monoid under AuthenticatorOr, then this
--   is the identity.
data Strict = Strict

data StrictDenial = StrictDenial
  deriving (Show)

instance Authenticator Strict where
  type NotAuthenticReason Strict s = StrictDenial
  type Subject Strict t = t
  type Challenge Strict s = ()
  authenticate Strict proxy subject challenge = return $ Just StrictDenial
