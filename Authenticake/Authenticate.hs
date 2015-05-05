{-# LANGUAGE AutoDeriveTypeable #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE DeriveFunctor #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE FlexibleContexts #-}

module Authenticake.Authenticate (

    Authenticate
  , authenticatedThing
  , withAuthentication

  , Authenticator(..)
  , Authenticates(..)
  , AuthenticationContext(..)

  , AuthenticationDecision

  , AuthenticatorOr
  , AuthenticatorAnd

  ) where

import Control.Applicative
import Control.Monad
import Control.Monad.IO.Class
import Control.Monad.Trans.Reader
import Control.Monad.Trans.Class
import Data.Proxy

newtype Authenticate ctx t m a = Authenticate {
    runAuthenticate :: ReaderT t m a
  } deriving (Functor, Applicative, Monad)

authenticatedThing :: Monad m => Authenticate ctx t m t
authenticatedThing = Authenticate ask

instance MonadTrans (Authenticate ctx t) where
  lift = Authenticate . lift

withAuthentication
  :: forall ctx t m a .
     ( MonadIO m
     , AuthenticationContext ctx
     , Authenticates ctx t
     , Authenticator (AuthenticationAgent ctx)
     )
  => ctx
  -> t
  -> Challenge (AuthenticationAgent ctx) t
  -> (NotAuthenticReason (AuthenticationAgent ctx) t -> m a)
  -> Authenticate ctx t m a
  -> m a
withAuthentication ctx datum challenge ifInvalid term = do
    let subject = toSubject ctx datum
    let agent = authenticationAgent ctx
    decision <- authenticate agent (Proxy :: Proxy t) subject challenge
    case decision of
        Just reason -> ifInvalid reason
        Nothing -> runReaderT (runAuthenticate term) datum
        -- ^ The datum which was authenticated is always given to the reader.
        --   This is very important.

-- | TBD get rid of Authenticator class and instead use
--
--   class Authenticates ctx t where
--     type NotAuthenticReason ctx t
--     type Challenge ctx t
--     authenticate
--       :: (
--          )
--       => ctx
--       -> t
--       -> Challenge ctx t
--       -> m (AuthenticationDecision ctx t)
--
--   This has one advantage: fewer classes, without more instances (there would
--   have been just as many instance in the alternative, but they'd be
--   the toSubject class instances.
--
--   Any disadvantages? What if we wanted to do generic password auth.
--   Seems with this alternative we lose a way of static that some @ctx@ is
--   password auth, always, no matter the datum @t@.
--   The current style is more general. If you want the other style, just
--   use 
--     Subject ctx t = t
--     toSubject = const id
--   and you're good to go
--
--   So how do we explain the asymmetry between Authenticate and Authorize?
--   We have
--     Authenticator ctx
--     Authenticates ctx t
--     AuthenticationContext ctx
--   versus
--     Authorizer ctx t r
--     AuthorizationContext ctx
--   why not
--     Authorizer ctx
--     Authorizes ctx t r
--   ??
class Authenticator ctx where
  type NotAuthenticReason ctx t
  -- ^ Description of why authentication was denied.
  type Subject ctx t
  type Challenge ctx t
  authenticate
    :: ( MonadIO m
       )
    => ctx
    -> Proxy t
    -> Subject ctx t
    -> Challenge ctx t
    -> m (AuthenticationDecision ctx t)

class AuthenticationContext ctx => Authenticates ctx t where
  toSubject :: ctx -> t -> Subject (AuthenticationAgent ctx) t

class AuthenticationContext ctx where
  type AuthenticationAgent ctx
  authenticationAgent :: ctx -> AuthenticationAgent ctx

-- | A Just gives a reason for denial, and absence of a reason (Nothing) means
--   authentication succeeds.
type AuthenticationDecision ctx t = Maybe (NotAuthenticReason ctx t)

-- | An Authenticator which carries two Authenticators, and passes if and only
--   if at least one of them passes.
data AuthenticatorOr a b = AuthenticatorOr a b

data Pair a b = P a b

instance (Authenticator a, Authenticator b) => Authenticator (AuthenticatorOr a b) where

  type NotAuthenticReason (AuthenticatorOr a b) t = Pair (NotAuthenticReason a t) (NotAuthenticReason b t)
  type Subject (AuthenticatorOr a b) t = Pair (Subject a t) (Subject b t)
  type Challenge (AuthenticatorOr a b) t = Pair (Challenge a t) (Challenge b t)

  authenticate (AuthenticatorOr a b) proxy (P sA sB) (P cA cB) = do
      -- TBD do these in parallel? Probably not worth it.
      decisionA <- authenticate a proxy sA cA
      decisionB <- authenticate b proxy sB cB
      return (P <$> decisionA <*> decisionB)

-- TODO
-- use case for And/Or is that your AuthenticationContext points to one as its
-- agent. But we want to automatically figure out how to produce a subject and
-- challenge for a given Authenticates... If we defined Authenticates against
-- Authenticators rather than AuthenticationContexts we'd be alright... we
-- somehow must say if we have Authenticates ctx t... 
-- Ok, we could ditch the automatic Authenticates instances, and just have the
-- programmer write them. They're easy, anyway.

{-
instance
  ( Authenticates authA t
  , Authenticates authB t
  )
  => Authenticates (AuthenticatorOr authA authB) t where
  toSubject (AuthenticatorOr authA authB) t = P (toSubject authA t) (toSubject authB t)
-}

-- | An Authenticator which carries two Authenticators, and passes if and only
--   if both of them pass.
data AuthenticatorAnd a b = AuthenticatorAnd a b

instance (Authenticator a, Authenticator b) => Authenticator (AuthenticatorAnd a b) where

  type NotAuthenticReason (AuthenticatorAnd a b) t = Either (NotAuthenticReason a t) (NotAuthenticReason b t)
  type Subject (AuthenticatorAnd a b) t = Pair (Subject a t) (Subject b t)
  type Challenge (AuthenticatorAnd a b) t = Pair (Challenge a t) (Challenge b t)

  authenticate (AuthenticatorAnd a b) proxy (P sA sB) (P cA cB) = do
      -- TBD do these in parallel? Probably not worth it.
      decisionA <- authenticate a proxy sA cA
      decisionB <- authenticate b proxy sB cB
      return ((Left <$> decisionA) <|> (Right <$> decisionB))

{-
instance
  ( Authenticates authA t
  , Authenticates authB t
  )
  => Authenticates (AuthenticatorAnd authA authB) t where
  toSubject (AuthenticatorAnd authA authB) t = P (toSubject authA t) (toSubject authB t)
-}
