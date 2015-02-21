Authenticake
============

Aims to be a highly versatile and easy-to-use authentication black-box.

#Motivation

Authenticake provides the `Authenticated` type. This is nice to have because
it identifies, in the types, something which is authenticated within some
domain-specific context.

This type, for instance, guarantees that `launchMissiles` is called only if
the program has authenticated `()` in the `MissileSilo` context:

```Haskell
launchMissiles :: Authenticated MissileSilo () -> IO ()
```

The use of `()` indicates that we have a kind of user-free authentication, like
a house key: the key is the same for all key holders, but varies from door to
door (`MissileSilo` is the door in this anology).

User-based authentication is possible as well. A hypothetical banking program
might contain this type:

```Haskell
withdraw :: Authenticated BankAccount Client -> IO WithdrawReceipt
```

In this case we know that `withdraw` is called only if there is some
authenticated client; that client can be obtained through the function
`authenticatedValue`, and then used to do further work.

#Drivers

There are four drivers in this repository:

- Strict : never authenticates anything
- Nice : authenticates everything
- File : uses a text file to store username, password pairs with no obfuscation
- Pure : uses a Haskell Map to store username, password associations

But these are probably not very useful.

# Authenticake-Password

[Password authentication with salted digests](https://github.com/avieth/Authenticake-Password).
