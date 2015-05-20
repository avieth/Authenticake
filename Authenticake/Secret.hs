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
  , SecretComparison(..)
  , SecretNotAuthentic(..)

  ) where

import Authenticake.Authenticate

data SecretAuthenticator m s c d = SecretAuthenticator {
    getSecret :: s -> m (Maybe d)
  , setSecret :: s -> (Maybe c) -> m ()
  , checkSecret :: c -> d -> m SecretComparison
  }

data SecretComparison = Match | NoMatch

data SecretNotAuthentic s c = UnknownSubject s | BadChallenge s c
  deriving (Show)

instance Monad m => Authenticator (SecretAuthenticator m s c d) where

    type NotAuthenticReason (SecretAuthenticator m s c d) t = SecretNotAuthentic s c

    type Subject (SecretAuthenticator m s c d) t = s

    type Challenge (SecretAuthenticator m s c d) t = c

    type AuthenticatorF (SecretAuthenticator m s c d) = m

    authenticate authenticator proxy subject challenge = do
        maybeExistingSecret <- getSecret authenticator subject
        case maybeExistingSecret of
            Nothing -> return (Just (UnknownSubject subject))
            Just secret -> do
                outcome <- checkSecret authenticator challenge secret
                case outcome of
                    NoMatch -> return (Just (BadChallenge subject challenge))
                    Match -> return Nothing
