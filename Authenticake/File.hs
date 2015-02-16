{-# LANGUAGE TypeFamilies #-}

module Authenticake.File (

    File
  , file
  , FileFailure

  ) where

import qualified Data.Text as T
import Control.Exception
import Control.Applicative
import System.IO
import Data.Attoparsec.Text
import Authenticake.Authenticate

-- | A rather silly example, in which usernames and passwords are stored in
--   a text file, with no obfuscation.
--   Clearly this is not intended for use; it's just here as a first example
--   of an Authenticator instance.
data File = File {
    _filepath :: FilePath
  }

file :: FilePath -> File
file = File

data FileFailure
  = ReadError
  | UsernameNotFound
  | BadPassword
  deriving (Show)

lineParser :: Parser (T.Text, T.Text)
lineParser = (,) <$> takeTill ((==) ',') <* char ',' <*> takeText

instance Authenticator File where
  type Failure File = FileFailure
  type Subject File t = T.Text
  type Challenge File t = T.Text

  -- A rather ugly and probably unsafe definition of the flat file's
  -- decision: look for the first line in the file matching the username,
  -- and check the associated password.
  authenticatorDecision f _ subject challenge =
      catch checkFile catcher

    where

      catcher :: SomeException -> IO (Maybe FileFailure)
      catcher _ = return $ Just ReadError

      checkFile = bracket
        (openFile (_filepath f) ReadMode)
        (hClose)
        (\handle -> findMatch handle subject challenge)

      findMatch h subject challenge = do
        end <- hIsEOF h
        if not end
        then do
          line <- T.pack <$> hGetLine h
          let result = parseOnly lineParser line
          case result of
            Right (username, password) ->
              if username == subject
              then if (password == challenge)
                   then return Nothing
                   else return $ Just BadPassword
              else findMatch h subject challenge
            Left _ -> findMatch h subject challenge
        else return $ Just UsernameNotFound
