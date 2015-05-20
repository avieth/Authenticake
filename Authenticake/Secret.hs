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

data SecretAuthenticator m s c d t = SecretAuthenticator {
    getSecret :: s -> c -> m (Maybe d)
  , setSecret :: s -> Maybe c -> t -> m ()
  , checkSecret :: s -> c -> d -> m (Maybe t)
  }

data SecretNotAuthentic s c = UnknownSubject s c | BadChallenge s c
  deriving (Show)

instance Monad m => Authenticator (SecretAuthenticator m s c d t) where

    type NotAuthenticReason (SecretAuthenticator m s c d t) u = SecretNotAuthentic s c

    type Subject (SecretAuthenticator m s c d t) u = s

    type Challenge (SecretAuthenticator m s c d t) u = c

    type AuthenticatedThing (SecretAuthenticator m s c d t) u = t

    type AuthenticatorF (SecretAuthenticator m s c d t) = m

    authenticate authenticator proxy subject challenge = do
        maybeExistingSecret <- getSecret authenticator subject challenge
        case maybeExistingSecret of
            Nothing -> return (Left (UnknownSubject subject challenge))
            Just secret -> do
                outcome <- checkSecret authenticator subject challenge secret
                case outcome of
                    Nothing -> return (Left (BadChallenge subject challenge))
                    Just thing -> return (Right thing)
