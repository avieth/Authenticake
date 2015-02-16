{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE OverloadedStrings #-}

module Authenticate.PostgreSQL (

    PostgreSQL

  , postgresql

  , PostgreSQLFailure
  , PostgreSQLUpdateFailure

  ) where

import qualified Data.Text as T
import qualified Data.ByteString as BS
import Data.Byteable (toBytes)
import Data.Word
import Control.Exception
import Database.PostgreSQL.Simple
import Crypto.Hash
import Crypto.Random
import Authenticate.Authenticate

-- | Authenticator which uses PostgreSQL and a salted whirlpool digest.
--   Assumes an sqlite db with a table called 'authenticate' with three
--   columns:
--     id primary key not null
--     hash not null
--     salt not null
data PostgreSQL = PostgreSQL {
    postgresInfo :: ConnectInfo
  }

postgresql :: String -> Word16 -> String -> String -> String -> PostgreSQL
postgresql host port username password database =
  PostgreSQL $ ConnectInfo host port username password database

data PostgreSQLFailure
  = PostgreSQLUsernameNotFound
  | PostgreSQLUsernameNotUnique
  | PostgreSQLBadPassword
  | PostgreSQLNoConnection
  | PostgreSQLQueryError
  deriving (Show)

data PostgreSQLUpdateFailure
  = PostgreSQLUpdateNoConnection
  | PostgreSQLUpdateExecError
  deriving (Show)

instance Authenticator PostgreSQL where
  type Failure PostgreSQL = PostgreSQLFailure
  type Subject PostgreSQL t = BS.ByteString
  type Challenge PostgreSQL t = BS.ByteString
  authenticatorDecision (PostgreSQL info) _ key password =
      catch
        (bracket
          (connect info)
          (close)
          (\conn -> catch (checkTable conn) bottomLevelCatcher))
        (topLevelCatcher)

    where

      topLevelCatcher :: SomeException -> IO (Maybe PostgreSQLFailure)
      topLevelCatcher _ = return $ Just PostgreSQLNoConnection

      bottomLevelCatcher :: SomeException -> IO (Maybe PostgreSQLFailure)
      bottomLevelCatcher _ = return $ Just PostgreSQLQueryError

      queryString = "SELECT hash, salt FROM authenticate WHERE id=?"

      checkTable conn = do
        row <- query conn queryString [key] :: IO [(BS.ByteString, BS.ByteString)]
        case row of
          [] -> return $ Just PostgreSQLUsernameNotFound
          [(hash, salt)] -> return $ checkHash hash salt password
          _ -> return $ Just PostgreSQLUsernameNotUnique

      checkHash :: BS.ByteString -> BS.ByteString -> BS.ByteString -> Maybe PostgreSQLFailure
      checkHash referenceDigest salt password =
        let willHash = BS.append password salt
            digest = hash willHash :: Digest Whirlpool
        in  if toBytes digest == referenceDigest
            then Nothing
            else Just PostgreSQLBadPassword


instance MutableAuthenticator PostgreSQL where
  type UpdateFailure PostgreSQL = PostgreSQLUpdateFailure
  authenticatorUpdate (PostgreSQL info) _ key password =
      catch
        (bracket
          (connect info)
          (close)
          (\conn -> catch (updateTable conn) bottomLevelCatcher))
        (topLevelCatcher)

    where

      topLevelCatcher :: SomeException -> IO (Either PostgreSQLUpdateFailure PostgreSQL)
      topLevelCatcher _ = return $ Left PostgreSQLUpdateNoConnection

      bottomLevelCatcher :: SomeException -> IO (Either PostgreSQLUpdateFailure PostgreSQL)
      bottomLevelCatcher _ = return $ Left PostgreSQLUpdateExecError

      -- Approximate an "upsert"
      execUpdate = "UPDATE authenticate SET hash=?, salt=? WHERE id=?"
      execInsert = "INSERT INTO authenticate SELECT ?, ?, ? WHERE NOT EXISTS (SELECT * FROM authenticate WHERE id=?)"

      updateTable conn = do
        salt <- genSalt
        let willHash = BS.append password salt
            digest = hash willHash :: Digest Whirlpool
            bkey = Binary key
            bdigest = Binary (toBytes digest)
            bsalt = Binary salt
        execute conn execUpdate (bdigest, bsalt, bkey)
        execute conn execInsert (bkey, bdigest, bsalt, bkey)
        return $ Right (PostgreSQL info)

      genSalt :: IO BS.ByteString
      genSalt = do
        ep <- createEntropyPool
        let gen = cprgCreate ep :: SystemRNG
        let (bytes, _) = cprgGenerate 4 gen
        return bytes
