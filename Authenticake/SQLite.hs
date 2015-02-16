{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE OverloadedStrings #-}

module Authenticate.SQLite (

    SQLite

  , sqlite

  , SQLiteFailure
  , SQLiteUpdateFailure

  ) where

import qualified Data.Text as T
import qualified Data.ByteString as BS
import Data.Byteable (toBytes)
import Control.Exception
import Database.SQLite.Simple
import Crypto.Hash
import Crypto.Random
import Authenticate.Authenticate

-- | Authenticator which uses SQLite and a salted whirlpool digest.
--   Assumes an sqlite db with a table called 'authenticate' with three
--   columns:
--     id primary key not null
--     hash not null
--     salt not null
data SQLite = SQLite {
    dbFilepath :: FilePath
  }

sqlite :: FilePath -> SQLite
sqlite = SQLite

data SQLiteFailure
  = SQLiteUsernameNotFound
  | SQLiteUsernameNotUnique
  | SQLiteBadPassword
  | SQLiteNoConnection
  | SQLiteQueryError
  deriving (Show)

data SQLiteUpdateFailure
  = SQLiteUpdateNoConnection
  | SQLiteUpdateExecError
  deriving (Show)

instance Authenticator SQLite where
  type Failure SQLite = SQLiteFailure
  type Subject SQLite t = BS.ByteString
  type Challenge SQLite t = BS.ByteString
  authenticatorDecision (SQLite fp) _ key password =
      catch
        (bracket
          (open fp)
          (close)
          (\conn -> catch (checkTable conn) bottomLevelCatcher))
        (topLevelCatcher)

    where

      topLevelCatcher :: SomeException -> IO (Maybe SQLiteFailure)
      topLevelCatcher _ = return $ Just SQLiteNoConnection

      bottomLevelCatcher :: SomeException -> IO (Maybe SQLiteFailure)
      bottomLevelCatcher _ = return $ Just SQLiteQueryError

      queryString = "SELECT hash, salt FROM authenticate WHERE id=?"

      checkTable conn = do
        row <- query conn queryString [key] :: IO [(BS.ByteString, BS.ByteString)]
        case row of
          [] -> return $ Just SQLiteUsernameNotFound
          [(hash, salt)] -> return $ checkHash hash salt password
          _ -> return $ Just SQLiteUsernameNotUnique

      checkHash :: BS.ByteString -> BS.ByteString -> BS.ByteString -> Maybe SQLiteFailure
      checkHash referenceDigest salt password =
        let willHash = BS.append password salt
            digest = hash willHash :: Digest Whirlpool
        in  if toBytes digest == referenceDigest
            then Nothing
            else Just SQLiteBadPassword


instance MutableAuthenticator SQLite where
  type UpdateFailure SQLite = SQLiteUpdateFailure
  authenticatorUpdate (SQLite fp) _ key password =
      catch
        (bracket
          (open fp)
          (close)
          (\conn -> catch (updateTable conn) bottomLevelCatcher))
        (topLevelCatcher)

    where

      topLevelCatcher :: SomeException -> IO (Either SQLiteUpdateFailure SQLite)
      topLevelCatcher _ = return $ Left SQLiteUpdateNoConnection

      bottomLevelCatcher :: SomeException -> IO (Either SQLiteUpdateFailure SQLite)
      bottomLevelCatcher _ = return $ Left SQLiteUpdateExecError

      -- We rely on the primary-key-ness of id.
      execString = "INSERT OR REPLACE INTO authenticate VALUES (?, ?, ?)"

      updateTable conn = do
        salt <- genSalt
        let willHash = BS.append password salt
            digest = hash willHash :: Digest Whirlpool
        execute conn execString (key, toBytes digest, salt)
        return $ Right (SQLite fp)

      genSalt :: IO BS.ByteString
      genSalt = do
        ep <- createEntropyPool
        let gen = cprgCreate ep :: SystemRNG
        let (bytes, _) = cprgGenerate 4 gen
        return bytes
