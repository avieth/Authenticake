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

-- One way to authenticate is via a session token. The program sets a secret
-- token for a user, and if somebody claims to be that user, and supplies the
-- matching token, then we judge them authentic.
-- How does this authenticator differ from a password authenticator?
--
--   Similarities:
--   1. each must pull a datum from somewhere (salt + hash, session token)
--      based on a subject.
--   2. each must use the challenge and that datum to make a decision.
--
--   Differences:
--   1. password store uses a salted hash, but
--
-- With session, there's no hashing; the challenge is compared with what's
-- in the DB.
--

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
