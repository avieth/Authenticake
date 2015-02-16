{-# LANGUAGE TypeFamilies #-}

module Authenticake.Strict (

    Strict(..)
  , StrictFailure

  ) where

import Authenticake.Authenticate

-- | The StrictAuthenticator never authenticates anybody.
data Strict = Strict

data StrictFailure = StrictDenied
  deriving (Show)

instance Authenticator Strict where
  type Failure Strict = StrictFailure
  type Subject Strict t = t
  type Challenge Strict t = ()
  authenticatorDecision _ _ _ _ = return $ Just StrictDenied
