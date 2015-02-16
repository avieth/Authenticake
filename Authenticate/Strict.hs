{-# LANGUAGE TypeFamilies #-}

module Authenticate.Strict (

    Strict

  ) where

import Authenticate.Authenticate

-- | The StrictAuthenticator never authenticates anybody.
data Strict = Strict

data StrictFailure = StrictDenied
  deriving (Show)

instance Authenticator Strict where
  type Failure Strict = StrictFailure
  type Subject Strict t = t
  type Challenge Strict t = ()
  authenticatorDecision _ _ _ _ = return $ Just StrictDenied
