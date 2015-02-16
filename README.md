Authenticake
============

Aims to be a highly versatile and easy-to-use authentication black-box.

#Drivers

There are four drivers in this repository:

- Strict : never authenticates anything
- Nice : authenticates everything
- File : uses a text file to store username, password pairs with no obfuscation
- Pure : uses a Haskell Map to store username, password associations

But these are probably not very useful.

## PostgreSQL

See [Authenticake-PostgreSQL](https://github.com/avieth/Authenticake-PostgreSQL).

## SQLite

See [Authenticake-SQLite](https://github.com/avieth/Authenticake-SQLite).
