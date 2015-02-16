{-# LANGUAGE MultiParamTypeClasses #-}

import qualified Data.Text as T
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as B8
import Authenticate.Authenticate
import Authenticate.SQLite
import Control.RichConditional
import System.Environment (getArgs)

data User = User BS.ByteString

instance Authenticatable SQLite User where
  authenticationSubject _ (User b) = b

main = do
    [filepath, action, username, password] <- getArgs
    let user = User (B8.pack username)
    let auther = sqlite filepath
    if action == "set"
    then do result <- setAuthentication auther user (B8.pack password)
            ifElse result ifUpdated ifNotUpdated
    else if action == "check"
         then do decision <- authenticate auther user (B8.pack password)
                 ifElse decision ifAuthenticated ifNotAuthenticated
         else return ()

  where

    ifAuthenticated :: Authenticated User -> IO ()
    ifAuthenticated _ = putStrLn "Authenticated!"

    ifNotAuthenticated :: SQLiteFailure -> IO ()
    ifNotAuthenticated f = putStrLn "Not authenticated!" >> print f

    ifUpdated :: SQLite -> IO ()
    ifUpdated _ = putStrLn "Updated!"

    ifNotUpdated :: SQLiteUpdateFailure -> IO ()
    ifNotUpdated f = putStrLn "Not updated!" >> print f
