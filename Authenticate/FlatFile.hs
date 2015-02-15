{-# LANGUAGE TypeFamilies #-}

module Authenticate.FlatFile (

    FlatFile
  , flatFile
  , FlatFileFailure

  ) where

import qualified Data.Text as T
import Control.Exception
import Control.Applicative
import System.IO
import Data.Attoparsec.Text
import Authenticate.Authenticate

-- | A rather silly example, in which usernames and passwords are stored in
--   a text file, with no obfuscation.
data FlatFile = FlatFile {
    _filepath :: FilePath
  }

flatFile :: FilePath -> FlatFile
flatFile = FlatFile

data FlatFileFailure
  = ReadError
  | UsernameNotFound
  | BadPassword
  deriving (Show)

lineParser :: Parser (T.Text, T.Text)
lineParser = (,) <$> takeTill ((==) ',') <* char ',' <*> takeText

instance Authenticator FlatFile where
  type Failure FlatFile = FlatFileFailure
  type Subject FlatFile t = T.Text
  type Challenge FlatFile t = T.Text

  -- A rather ugly and probably unsafe definition of the flat file's
  -- decision: look for the first line in the file matching the username,
  -- and check the associated password.
  authenticatorDecision flatFile _ subject challenge =
      catch checkFile catcher

    where

      catcher :: SomeException -> IO (Maybe FlatFileFailure)
      catcher _ = return $ Just ReadError

      checkFile = bracket
        (openFile (_filepath flatFile) ReadMode)
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
    
