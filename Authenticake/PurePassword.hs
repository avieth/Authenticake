{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE FlexibleContexts #-}

module Authenticake.PurePassword (

    PurePassword
  , purePassword

  ) where

import qualified Data.Text as T
import qualified Data.Map as M
import Control.Applicative
import Control.Monad.Trans.State
import Authenticake.Authenticate
import Authenticake.Secret

type PurePassword = SecretAuthenticator (State (M.Map T.Text T.Text)) T.Text T.Text T.Text

purePassword :: PurePassword
purePassword = SecretAuthenticator getPwd setPwd checkPwd

  where

    getPwd :: T.Text -> State (M.Map T.Text T.Text) (Maybe T.Text)
    getPwd subject = do
        map <- get
        return (M.lookup subject map)

    setPwd :: T.Text -> Maybe T.Text -> State (M.Map T.Text T.Text) ()
    setPwd subject challenge = do
        map <- get
        put (M.update (const challenge) subject map)

    checkPwd :: T.Text -> T.Text -> State (M.Map T.Text T.Text) SecretComparison
    checkPwd challenge pwd =
        if challenge == pwd
        then return Match
        else return NoMatch
