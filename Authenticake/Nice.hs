{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE StandaloneDeriving #-}

module Authenticake.Nice (

    Nice(..)
  , NiceDenial

  ) where

import Authenticake.Authenticate
import Data.Functor.Identity

-- | The NiceAuthenticator authenticates everybody.
--   If Authenticator instances form a monoid under AuthenticatorAnd, then this
--   is the identity.
data Nice = Nice

data NiceDenial

deriving instance Show NiceDenial

instance Authenticator Nice where
  type NotAuthenticReason Nice s = NiceDenial
  type Subject Nice t = t
  type Challenge Nice s = ()
  type AuthenticatorF Nice = Identity
  authenticate Nice proxy subject challenge = return Nothing
