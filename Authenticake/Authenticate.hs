{-# LANGUAGE AutoDeriveTypeable #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE DeriveFunctor #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE UndecidableInstances #-}

module Authenticake.Authenticate (

    Authenticate
  , authenticatedThing
  , authenticatedContext
  , withAuthentication
  , AuthenticationOutcome(..)

  , Authenticator(..)
  , Authenticates(..)
  , AuthenticationContext(..)

  , AuthenticationDecision

  --, AuthenticatorOr
  --, AuthenticatorAnd

  ) where

import Control.Applicative
import Control.Monad
import Control.Monad.IO.Class
import Control.Monad.Trans.Reader
import Control.Monad.Trans.Class
import Data.Proxy

newtype Authenticate ctx t m a = Authenticate {
    runAuthenticate :: ReaderT (ctx, t) m a
  } deriving (Functor, Applicative, Monad)

authenticatedContext :: (Functor m, Monad m) => Authenticate ctx t m ctx
authenticatedContext = Authenticate (fst <$> ask)

authenticatedThing :: (Functor m, Monad m) => Authenticate ctx t m t
authenticatedThing = Authenticate (snd <$> ask)

instance MonadTrans (Authenticate ctx t) where
  lift = Authenticate . lift

data AuthenticationOutcome ctx t a where
  AuthenticationFailed :: NotAuthenticReason (AuthenticationAgent ctx t) t -> AuthenticationOutcome ctx t a
  AuthenticationOK :: a -> AuthenticationOutcome ctx t a

deriving instance (Show a, Show (NotAuthenticReason (AuthenticationAgent ctx t) t))
  => Show (AuthenticationOutcome ctx t a)

instance Functor (AuthenticationOutcome ctx t) where
  fmap f term = case term of
      AuthenticationFailed x -> AuthenticationFailed x
      AuthenticationOK x -> AuthenticationOK (f x)

withAuthentication
  :: forall ctx t m a .
     ( AuthenticationContext ctx t
     , Authenticates ctx t
     , Authenticator (AuthenticationAgent ctx t)
     , Functor m
     , Monad m
     )
  => ctx
  -> (forall r . AuthenticatorF (AuthenticationAgent ctx t) r -> m r)
  -> t
  -> Challenge (AuthenticationAgent ctx t) t
  -> Authenticate ctx t m a
  -> m (AuthenticationOutcome ctx t a)
withAuthentication ctx lifter datum challenge term = do
    let subject = toSubject ctx datum
    let agent = authenticationAgent ctx (Proxy :: Proxy t)
    decision <- lifter $ authenticate agent (Proxy :: Proxy t) subject challenge
    case decision of
        Just reason -> return (AuthenticationFailed reason)
        Nothing -> fmap AuthenticationOK (runReaderT (runAuthenticate term) (ctx, datum))

class Authenticator ctx where
  type NotAuthenticReason ctx t
  -- ^ Description of why authentication was denied.
  type Subject ctx t
  type Challenge ctx t
  type AuthenticatorF ctx :: * -> *
  authenticate
    :: (
       )
    => ctx
    -> Proxy t
    -> Subject ctx t
    -> Challenge ctx t
    -> (AuthenticatorF ctx) (AuthenticationDecision ctx t)

class AuthenticationContext ctx t => Authenticates ctx t where
  toSubject :: ctx -> t -> Subject (AuthenticationAgent ctx t) t

class AuthenticationContext ctx t where
  type AuthenticationAgent ctx t
  authenticationAgent :: ctx -> Proxy t -> AuthenticationAgent ctx t

-- | A Just gives a reason for denial, and absence of a reason (Nothing) means
--   authentication succeeds.
type AuthenticationDecision ctx t = Maybe (NotAuthenticReason ctx t)

{-
-- | An Authenticator which carries two Authenticators, and passes if and only
--   if at least one of them passes.
data AuthenticatorOr a b = AuthenticatorOr a b

data Pair a b = P a b

instance
    ( Authenticator a
    , Authenticator b
    ) => Authenticator (AuthenticatorOr a b)
  where

    type NotAuthenticReason (AuthenticatorOr a b) t = Pair (NotAuthenticReason a t) (NotAuthenticReason b t)
    type Subject (AuthenticatorOr a b) t = Pair (Subject a t) (Subject b t)
    type Challenge (AuthenticatorOr a b) t = Pair (Challenge a t) (Challenge b t)

    authenticate (AuthenticatorOr a b) proxy (P sA sB) (P cA cB) =
        mkPair <$> authenticate a proxy sA cA <*> authenticate b proxy sB cB
      where
        mkPair maybe1 maybe2 = P <$> maybe1 <*> maybe2

-- | An Authenticator which carries two Authenticators, and passes if and only
--   if both of them pass.
data AuthenticatorAnd a b = AuthenticatorAnd a b

instance
    ( Authenticator a
    , Authenticator b
    ) => Authenticator (AuthenticatorAnd a b)
  where

    type NotAuthenticReason (AuthenticatorAnd a b) t = Either (NotAuthenticReason a t) (NotAuthenticReason b t)
    type Subject (AuthenticatorAnd a b) t = Pair (Subject a t) (Subject b t)
    type Challenge (AuthenticatorAnd a b) t = Pair (Challenge a t) (Challenge b t)

    authenticate (AuthenticatorAnd a b) proxy (P sA sB) (P cA cB) =
        chooseEither <$> authenticate a proxy sA cA <*> authenticate b proxy sB cB
      where
        chooseEither maybe1 maybe2 = (Left <$> maybe1) <|> (Right <$> maybe2)
-}
