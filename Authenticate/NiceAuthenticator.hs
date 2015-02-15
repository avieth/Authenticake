{-# LANGUAGE TypeFamilies #-}

module Authenticate.NiceAuthenticator (

    NiceAuthenticator

  ) where

import Authenticate.Authenticate

-- | The NiceAuthenticator authenticates everybody.
data NiceAuthenticator = NiceAuthenticator

data NiceAuthenticatorFailure

instance Authenticator NiceAuthenticator where
  type Failure NiceAuthenticator = NiceAuthenticatorFailure
  type Subject NiceAuthenticator t = t
  type Challenge NiceAuthenticator t = ()
  authenticatorDecision _ _ _ _ = return Nothing
