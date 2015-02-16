Authenticator
=============

Aims to be a highly versatile and easy-to-use authentication black-box.

#Examples

## SQLite

Find in `examples/SQLite.hs` an example program which is backed by SQLite3
and the sqlite-simple package. It takes 4 command-line arguments:

- Path to an sqlite database file
- `set` or `check`
- a username
- a password

```Bash
$ ./SQLite authenticate.sqlite set Twemlow nerv0us
$ ./SQLite authenticate.sqlite check Twemlow nerv0us
$ ./SQLite authenticate.sqlite check Twemlow conf1dent
```
