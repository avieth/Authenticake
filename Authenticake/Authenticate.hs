{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE PatternSynonyms #-}

module Authenticake.Authenticate (

    authenticate
  , setAuthentication

  , Authenticated
  , AuthenticateDecision

  , pattern AuthenticationOK
  , pattern AuthenticationFailed

  , AuthenticatorUpdateDecision

  , pattern AuthenticatorUpdateOK
  , pattern AuthenticatorUpdateFailed

  , Authenticator(..)
  , MutableAuthenticator(..)
  , Authenticatable(..)
  , AuthenticationContext(..)

  , authenticatedValue

  , AuthenticatorOr(..)
  , AuthenticatorAnd(..)
  , Pair(..)
  , Left(..)
  , Right(..)

  ) where

import Control.Applicative
import Control.RichConditional
import Data.Proxy

-- | The main user-facing function
authenticate
  :: forall ctx t .
     ( AuthenticationContext ctx
     , Authenticatable (AuthenticatingAgent ctx) t
     , Authenticator (AuthenticatingAgent ctx)
     )
  => ctx
  -> t
  -> Challenge (AuthenticatingAgent ctx) (Subject (AuthenticatingAgent ctx) t)
  -> IO (AuthenticateDecision ctx t)
authenticate ctx x c = do
  let agent = authenticatingAgent ctx
  let subject = authenticationSubject (Proxy :: Proxy (AuthenticatingAgent ctx)) x
  decision <- authenticatorDecision agent (Proxy :: Proxy t) subject c
  -- The decision is positive in case of a failure, so we use Bad in the
  -- positive case and give Authenticated otherwise.
  return $ inCase decision Bad (OK (Authenticated x))

setAuthentication
  :: forall ctx authenticator t .
     ( AuthenticationContext ctx
     , authenticator ~ AuthenticatingAgent ctx
     , Authenticatable authenticator t
     , MutableAuthenticator authenticator
     )
  => ctx 
  -> t
  -> Challenge authenticator (Subject authenticator t)
  -> IO (AuthenticatorUpdateDecision ctx t)
setAuthentication ctx x c = do
  let agent = authenticatingAgent ctx
  let subject = authenticationSubject (Proxy :: Proxy (AuthenticatingAgent ctx)) x
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
  | Bad (Failure (AuthenticatingAgent ctx) (Subject (AuthenticatingAgent ctx) a))
  -- ^ Not authenticated.

-- We don't export the AuthenticateDecision constructors, but we do export
-- pattern synonyms, to facilitate the use of this datatype.
-- They can also be consumed through their PartialIf and TotalIf instances
-- (inCase and ifElse).
pattern AuthenticationOK x <- OK x
pattern AuthenticationFailed x <- Bad x

instance PartialIf (AuthenticateDecision ctx a) (Authenticated ctx a) where
  indicate auth = case auth of
    OK x -> Just x
    _ -> Nothing

instance f ~ Failure (AuthenticatingAgent ctx) (Subject (AuthenticatingAgent ctx) a) => TotalIf (AuthenticateDecision ctx a) (Authenticated ctx a) f where
  decide auth = case auth of
    OK x -> Left x
    Bad x -> Right x

data AuthenticatorUpdateDecision ctx t
  = UpdateOK (AuthenticatingAgent ctx)
  | UpdateFailed (UpdateFailure (AuthenticatingAgent ctx) (Subject (AuthenticatingAgent ctx) t))

pattern AuthenticatorUpdateOK x <- UpdateOK x
pattern AuthenticatorUpdateFailed x <- UpdateFailed x

instance f ~ UpdateFailure (AuthenticatingAgent ctx) (Subject (AuthenticatingAgent ctx) t) => PartialIf (AuthenticatorUpdateDecision ctx t) f where
  indicate authMutate = case authMutate of
    UpdateOK _ -> Nothing
    UpdateFailed y -> Just y

instance (agent ~ AuthenticatingAgent ctx, f ~ UpdateFailure agent (Subject agent t)) => TotalIf (AuthenticatorUpdateDecision ctx t) agent f where
  decide authMutate = case authMutate of
    UpdateOK x -> Left x
    UpdateFailed x -> Right x

class Authenticator a where
  type Subject a t :: *
  -- ^ The subject can depend upon the thing being authenticated.
  type Challenge a subject :: *
  -- ^ The challenge can depend upon the subject.
  type Failure a subject :: *
  -- ^ Type to describe every possible reason for authentication failure.
  --   This may vary between Authenticators: for instance, a username/password
  --   based Authenticator can say "wrong password", "unrecognized username",
  --   or "database I/O problem", but an OAuth based Authenticator would say
  --   "invalid key" or something.
  --   It depends upon the subject.
  authenticatorDecision
    :: (
       )
    => a
    -> u t
    -- ^ A proxy for the thing being authenticated; needed since Subject and
    --   Challenge are not injective.
    -> Subject a t
    -> Challenge a (Subject a t)
    -> IO (Maybe (Failure a (Subject a t)))

class Authenticator a => MutableAuthenticator a where
  type UpdateFailure a subject :: *
  authenticatorUpdate
    :: (
       )
    => a
    -> u t
    -> Subject a t
    -> Challenge a (Subject a t)
    -> IO (Either (UpdateFailure a (Subject a t)) a)

class Authenticatable authenticator t where
  authenticationSubject :: u authenticator -> t -> Subject authenticator t

class AuthenticationContext ctx where
  type AuthenticatingAgent ctx :: *
  authenticatingAgent :: ctx -> AuthenticatingAgent ctx

-- | An Authenticator which carries two Authenticators, and passes if and only
--   if at least one of them passes.
data AuthenticatorOr a b = AuthenticatorOr a b

data Left a = L a
data Right a = R a

-- | An Authenticator which carries two Authenticators, and passes if and only
--   if both of them pass.
data AuthenticatorAnd a b = AuthenticatorAnd a b

data Pair a b = P a b

instance (Authenticator a, Authenticator b) => Authenticator (AuthenticatorOr a b) where

  type Failure (AuthenticatorOr a b) (Pair s0 s1) = Pair (Failure a s0) (Failure b s1)
  -- Subject have to in some sense "agree". The instances of
  -- Authenticatable for AuthenticatorOr facilitate this.
  type Subject (AuthenticatorOr a b) t = Pair (Subject a t) (Subject b t)
  type Challenge (AuthenticatorOr a b) (Pair s0 s1) = Pair (Challenge a s0) (Challenge b s1)

  authenticatorDecision (AuthenticatorOr a b) proxy (P sA sB) (P cA cB) = do
      -- TBD do these in parallel? Probably not worth it.
      decisionA <- authenticatorDecision a proxy sA cA
      decisionB <- authenticatorDecision b proxy sB cB
      return (P <$> decisionA <*> decisionB)
   
instance (Authenticator a, Authenticator b) => Authenticator (AuthenticatorAnd a b) where

  type Failure (AuthenticatorAnd a b) (Pair s0 s1) = Either (Failure a s0) (Failure b s1)
  type Subject (AuthenticatorAnd a b) t = Pair (Subject a t) (Subject b t)
  type Challenge (AuthenticatorAnd a b) (Pair s0 s1) = Pair (Challenge a s0) (Challenge b s1)

  authenticatorDecision (AuthenticatorAnd a b) proxy (P sA sB) (P cA cB) = do
      -- TBD do these in parallel? Probably not worth it.
      decisionA <- authenticatorDecision a proxy sA cA
      decisionB <- authenticatorDecision b proxy sB cB
      return ((Left <$> decisionA) <|> (Right <$> decisionB))

instance
  ( Authenticatable authA t
  , Authenticatable authB t
  ) => Authenticatable (AuthenticatorOr authA authB) t where
  authenticationSubject _ t =
      P (authenticationSubject proxyA t) (authenticationSubject proxyB t)
    where
      proxyA :: Proxy authA
      proxyA = Proxy
      proxyB :: Proxy authB
      proxyB = Proxy

instance
  ( Authenticatable authA t
  , Authenticatable authB t
  ) => Authenticatable (AuthenticatorAnd authA authB) t where
  authenticationSubject _ t =
      P (authenticationSubject proxyA t) (authenticationSubject proxyB t)
    where
      proxyA :: Proxy authA
      proxyA = Proxy
      proxyB :: Proxy authB
      proxyB = Proxy
