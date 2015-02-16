{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Authenticake.Authenticate (

    authenticate
  , Authenticated
  , AuthenticateDecision

  , AuthenticatorMutateDecision
  , setAuthentication

  , Authenticator(..)
  , MutableAuthenticator(..)
  , Authenticatable(..)
  , AuthenticationContext(..)

  , authenticatedValue

  ) where

import Control.RichConditional
import Data.Proxy

-- | The main user-facing function
authenticate
  :: forall ctx authenticator t .
     ( AuthenticationContext ctx
     , Authenticatable ctx t
     , authenticator ~ AuthenticatingAgent ctx
     , Authenticator authenticator
     )
  => ctx
  -> t
  -> Challenge authenticator t
  -> IO (AuthenticateDecision ctx t)
authenticate ctx x c = do
  let agent = authenticatingAgent ctx
  let subject = authenticationSubject (Proxy :: Proxy ctx) x
  decision <- authenticatorDecision agent (Proxy :: Proxy t) subject c
  -- The decision is positive in case of a failure, so we use Bad in the
  -- positive case and give Authenticated otherwise.
  return $ inCase decision Bad (OK (Authenticated x))

setAuthentication
  :: forall ctx authenticator t .
     ( AuthenticationContext ctx
     , Authenticatable ctx t
     , authenticator ~ AuthenticatingAgent ctx
     , MutableAuthenticator authenticator
     )
  => ctx 
  -> t
  -> Challenge authenticator t
  -> IO (AuthenticatorMutateDecision ctx t)
setAuthentication ctx x c = do
  let agent = authenticatingAgent ctx
  let subject = authenticationSubject (Proxy :: Proxy ctx) x
  result <- authenticatorUpdate agent (Proxy :: Proxy t) subject c
  return $ ifElse 
    result
    (UpdateFailed)
    (UpdateOK)

-- | Indicates that some value of type a is authenticated
--   It's important that we do not export Authenticated.
--   'authenticate' is the only function which will create Authenticated
--   values.
--   The phantom type is there to indicate the means by which the thing was
--   authenticated. In practice, this will be some domain-specific type.
data Authenticated ctx a = Authenticated a

authenticatedValue :: Authenticated ctx a -> a
authenticatedValue (Authenticated x) = x

-- | A decision about authentication for a value of some type a.
data AuthenticateDecision ctx a
  = OK (Authenticated ctx a)
  -- ^ Authenticated.
  | Bad (Failure (AuthenticatingAgent ctx))
  -- ^ Not authenticated.

instance PartialIf (AuthenticateDecision ctx a) (Authenticated ctx a) where
  indicate auth = case auth of
    OK x -> Just x
    _ -> Nothing

instance f ~ Failure (AuthenticatingAgent ctx) => TotalIf (AuthenticateDecision ctx a) (Authenticated ctx a) f where
  decide auth = case auth of
    OK x -> Left x
    Bad x -> Right x

data AuthenticatorMutateDecision ctx t
  = UpdateOK (AuthenticatingAgent ctx)
  | UpdateFailed (UpdateFailure (AuthenticatingAgent ctx))

instance f ~ UpdateFailure (AuthenticatingAgent ctx) => PartialIf (AuthenticatorMutateDecision ctx t) f where
  indicate authMutate = case authMutate of
    UpdateOK _ -> Nothing
    UpdateFailed y -> Just y

instance (agent ~ AuthenticatingAgent ctx, f ~ UpdateFailure agent) => TotalIf (AuthenticatorMutateDecision ctx t) agent f where
  decide authMutate = case authMutate of
    UpdateOK x -> Left x
    UpdateFailed x -> Right x

class Authenticator a where
  type Failure a :: *
  -- ^ Type to describe every possible reason for authentication failure.
  --   This may vary between Authenticators: for instance, a username/password
  --   based Authenticator can say "wrong password", "unrecognized username",
  --   or "database I/O problem", but an OAuth based Authenticator would say
  --   "invalid key" or something.
  type Subject a t :: *
  type Challenge a t :: *
  authenticatorDecision
    :: (
       )
    => a
    -> u t
    -- ^ A proxy; needed since Subject and Challenge are not injective.
    -> Subject a t
    -> Challenge a t
    -> IO (Maybe (Failure a))

class Authenticator a => MutableAuthenticator a where
  type UpdateFailure a :: *
  authenticatorUpdate
    :: (
       )
    => a
    -> u t
    -> Subject a t
    -> Challenge a t
    -> IO (Either (UpdateFailure a) a)

class Authenticatable ctx t where
  authenticationSubject :: u ctx -> t -> Subject (AuthenticatingAgent ctx) t

class AuthenticationContext ctx where
  type AuthenticatingAgent ctx :: *
  authenticatingAgent :: ctx -> AuthenticatingAgent ctx
