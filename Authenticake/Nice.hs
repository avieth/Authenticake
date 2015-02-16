{-# LANGUAGE TypeFamilies #-}

module Authenticake.Nice (

    Nice(..)

  ) where

import Authenticake.Authenticate

-- | The NiceAuthenticator authenticates everybody.
data Nice = Nice

data NiceFailure

instance Authenticator Nice where
  type Failure Nice = Nice
  type Subject Nice t = t
  type Challenge Nice t = ()
  authenticatorDecision _ _ _ _ = return Nothing
