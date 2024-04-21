# Homomorphic Authentication 

## Introduction
An authentication protocol based on homomorphic encryption.
The premise is that a user's password is the key to decode a random bit vector that is used to verify the user.
If the databse is leaked, ideally no information about the password should be exposed as the password is not encoded, but rather random information.

> Note:
> 
> I have not proven this out, and as such wouldn't trust this to protect any information.
> This was just a fun project to dip my toes into the realm of [Homomorphic Encryption](https://en.wikipedia.org/wiki/Homomorphic_encryption) using the [go-tfhe library](https://github.com/thedonutfactory/go-tfhe).

## Description
The protocol is split into the sign up and login steps.
### Sign Up
In the sign up step, a client seeks to register a user with a username and password.
The password is used to generate a public-private key packet.
The client generates a random `[n]byte` vector such that `n` is even.
The first half of the vector serves as an XOR mask to the secret, `vector[:n/2]^vector[n/2:]`.
The client uses the private key to encrypt this vector to make the `encryptedPayload`.
The client then sends the `{username, encryptedPayload, secret}` tuple to the server.

The server hashes and salts the secret, and stores the `{username, encryptedPayload, salt, saltedHash}` tuple in a database.

### Login

#### Phase 1
The client uses the password to generate a public-private key packet.
The client then sends the `{username, publicKey}` tuple to the server.

The server uses the `username` to retrieve the `encryptedPayload` from the sign up step.
Using the `encryptedPayload`, an `encryptedMutation` is computed such that the upper and lower halves of its binary representation are equivalent.
By XORing the `encryptedPayload` and `encryptedMutation`, the server generates a `encryptedMutatedPayload`.
The server returns the `{encryptedMutatedPayload}` to the client.

#### Phase 2
The client uses the private key to decrypt the `encryptedMutatedPayload`.
We know the `encryptedMutation` did not change the vector XOR property from the sign up step.
The client then computes the `decryptedSecret` by calculating `decryptedMutatedPayload[:n/2]^decryptedMutatedPayload[n/2:]`.
The client makes a second request to the server with the `{username, decryptedSecret}` tuple.

The server uses the `username` to retrieve the `{salt, saltedHash}` tuple from the sign up step.
The server computes the `decryptedSecretSaltedHash` from the `decryptedSecret` and `salt`.
Comparing the `decryptedSecretSaltedHash` and `saltedHash`, the server responds with a successful or failed authetication.

## Example
An example is provided in `example/` that spins up a server and client to perform the authentication protocol.
Run it from the workspace directory with `go run ./example/...`.
It will print out the `secret` and `decryptedSecret` to standard out.