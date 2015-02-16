{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE MultiParamTypeClasses #-}

import qualified Data.Text as T
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as B8
import Authenticate.Authenticate
import Authenticate.PostgreSQL
import Control.RichConditional
import System.Environment (getArgs)

data ExampleDomain = ExampleDomain PostgreSQL

instance AuthenticationContext ExampleDomain where
  type AuthenticatingAgent ExampleDomain = PostgreSQL
  authenticatingAgent (ExampleDomain sqlite) = sqlite

data User = User BS.ByteString

instance Authenticatable ExampleDomain User where
  authenticationSubject _ (User b) = b

main = do
    [dbname, action, username, password] <- getArgs
    let user = User (B8.pack username)
    let auther = ExampleDomain (postgresql "localhost" (fromIntegral 5432) "" "" dbname)
    if action == "set"
    then do result <- setAuthentication auther user (B8.pack password)
            ifElse result ifUpdated ifNotUpdated
    else if action == "check"
         then do decision <- authenticate auther user (B8.pack password)
                 ifElse decision ifAuthenticated ifNotAuthenticated
         else return ()

  where

    ifAuthenticated :: Authenticated ExampleDomain User -> IO ()
    ifAuthenticated _ = putStrLn "Authenticated!"

    ifNotAuthenticated :: PostgreSQLFailure -> IO ()
    ifNotAuthenticated f = putStrLn "Not authenticated!" >> print f

    ifUpdated :: PostgreSQL -> IO ()
    ifUpdated _ = putStrLn "Updated!"

    ifNotUpdated :: PostgreSQLUpdateFailure -> IO ()
    ifNotUpdated f = putStrLn "Not updated!" >> print f
