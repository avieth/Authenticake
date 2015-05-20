{-|
Module      : Authenticake.Secret
Description : Authentication based on a secret piece of data.
Copyright   : (c) Alexander Vieth, 2015
Licence     : BSD3
Maintainer  : aovieth@gmail.com
Stability   : experimental
Portability : non-portable (GHC only)
-}

{-# LANGUAGE AutoDeriveTypeable #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE TypeFamilies #-}

module Authenticake.Secret (

    SecretAuthenticator(..)
  , SecretNotAuthentic(..)

  ) where

import Authenticake.Authenticate

-- | An authenticator which uses a secret datum to do its job.
--   
--     - @m@ is the functor in which computation takes place
--     - @s@ is the subject
--     - @fc@ is the functor to wrap the challenge in setSecret
--     - @c@ is the challenge
--     - @d@ is the secret
--     - @ft@ is the functor to wrap the authenticated thing in setSecret
--     - @t@ is the authenticated thing
--
--   A subject and challenge come together to determine a maybe secret.
--   A subject, challenge, and secret come together to determine a maybe
--   authenticated thing.
--
--   If s = t, ft = Const (), fc = Maybe, then we have something which
--   resembles a password authentication system, with s representing username,
--   c representing password, and d some sort of digest.
--
--   If d = t, s = (), ft = Maybe, fc = Identity, then we have something
--   which resembles a token-based authentication system, with t representing
--   username, and c the token.
--
data SecretAuthenticator m s c fc t ft d = SecretAuthenticator {
    getSecret :: s -> c -> m (Maybe d)
  , setSecret :: s -> fc c -> ft t -> m ()
  , checkSecret :: s -> c -> d -> m (Maybe t)
  }

data SecretNotAuthentic s c = UnknownSubject s c | BadChallenge s c
  deriving (Show)

instance
    ( Monad m
    ) => Authenticator (SecretAuthenticator m s c fc t ft d)

  where

    type NotAuthenticReason (SecretAuthenticator m s c fc t ft d) u = SecretNotAuthentic s c

    type Subject (SecretAuthenticator m s c fc t ft d) u = s

    type Challenge (SecretAuthenticator m s c fc t ft d) u = c

    type AuthenticatedThing (SecretAuthenticator m s c fc t ft d) u = t

    type AuthenticatorF (SecretAuthenticator m s c fc t ft d) = m

    authenticate authenticator proxy subject challenge = do
        maybeExistingSecret <- getSecret authenticator subject challenge
        case maybeExistingSecret of
            Nothing -> return (Left (UnknownSubject subject challenge))
            Just secret -> do
                outcome <- checkSecret authenticator subject challenge secret
                case outcome of
                    Nothing -> return (Left (BadChallenge subject challenge))
                    Just thing -> return (Right thing)
