{-# LANGUAGE TypeFamilies #-}

module Authenticake.Nice (

    Nice(..)

  ) where

import Authenticake.Authenticate

-- | The NiceAuthenticator authenticates everybody.
--   If Authenticator instances form a monoid under AuthenticatorAnd, then this
--   is the identity.
data Nice = Nice

data NiceFailure

instance Authenticator Nice where
  type Failure Nice s = Nice
  type Subject Nice t = t
  type Challenge Nice s = ()
  authenticatorDecision _ _ _ _ = return Nothing
