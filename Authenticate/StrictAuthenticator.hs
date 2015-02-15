{-# LANGUAGE TypeFamilies #-}

module Authenticate.StrictAuthenticator (

    StrictAuthenticator

  ) where

import Authenticate.Authenticate

-- | The StrictAuthenticator never authenticates anybody.
data StrictAuthenticator = StrictAuthenticator

data StrictAuthenticatorFailure = StrictAuthenticatorDenied
  deriving (Show)

instance Authenticator StrictAuthenticator where
  type Failure StrictAuthenticator = StrictAuthenticatorFailure
  type Subject StrictAuthenticator t = t
  type Challenge StrictAuthenticator t = ()
  authenticatorDecision _ _ _ _ = return $ Just StrictAuthenticatorDenied
