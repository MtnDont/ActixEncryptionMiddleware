# actix_web End-to-End Encryption Middleware

### Preamble

Originally, I started this project as a couple of different ideas. Near the beginning of this project I had recently purchased equipment to use as a NAS and small server between friends. At the same time, the storage on my mobile devices was getting low, and I still wanted to be able to carry photos on my phone to share a moment or a laugh between friends.

I took this moment sit down and look at my understanding of security practices, learn Rust, and try some new things along the way.

This repository includes an example implementation into an actix_web project. It takes POST requests for files or directories and serves the content from them.

## Requirements

* Cargo
* This middleware assumes you have safely exchanged keys with the server. The Authorization identifier matches the name of the key.

## Usage

Clone this repository

```sh
$ git clone https://github.com/MtnDont/ActixEncryptionMiddleware
```

Copy src/encryption_middleware.rs, and src/keyset.rs, src/read_response_body.rs to your own repository.
```sh
$ cp src/encryption_middleware.rs src/keyset.rs src/read_response_body.rs /path/to/your/project/
```

Wrap your actix_web `App` with the associated Request and Response middleware

```rust
App::new()
    // Your index service for your server
    .service(index)
    // Enforces request end of end-to-end encryption
    .wrap(encryption_middleware::E2E)
    // Enforces response end of end-to-end encryption
    .wrap(read_response_body::EncryptedResponse)
```

Create a `.cargo/` directory at the base of your project and provide a `config.toml` with the follow variables:
```toml
[env]
key_name="server_key_name"
key_path="/path/to/server/and/client/keys/"
```

In your defined `key_path`, generate a private-public 256-bit XChaCha20Poly1305 keypair. \
The example below is one of many ways to generate these keys. Use this one or pick one you may trust more.
```sh
$ openssl rand 32 > server_key_name.pub
$ openssl rand 32 > server_key_name
```

This middleware <u>**_does not_**</u> handle key exchange, key invalidation, or sessions. It operates under the impression that key exchange has already been handled and that all user public keys exist in `key_path`. So make sure that you already have the requesters' public keys (stored as 32 byte .pub files) prior to data being processed through this middleware.

Run the server

```sh
cargo run --release
```

All incoming and outgoing data will now follow the [Expected Structure](#expected-structure) section.

### Notes
If you want only the response or request pieces encrypted, simply remove the offending wrapper.

I will say again, this middleware <u>**_does not_**</u> handle key exchange, key invalidation, or sessions. It operates under the impression that key exchange has already been handled and that all user public keys exist in `key_path`. So make sure that you already have the requesters' public keys (stored as 32 byte .pub files) prior to data being processed through this middleware.

## Expected Structure

### HTTP Request Header
```
Content-Type: <CONTENT-TYPE>
Authorization: Basic <BASE64-IDENTIFIER>
magicant-nonce: <BASE64-NONCE>
```
### HTTP Response Header
```
Content-Type: <CONTENT-TYPE>
magicant-nonce: <BASE64-NONCE>
```
### Encrypted Response Body Structure
```
+-----------------------+------------+-----------------------+------------+---------+
| 1st ciphertext len    | ciphertext | 2nd ciphertext len    | ciphertext |         |
+-----------------------+------------+-----------------------+------------+   ...   +
|        u_int32        |    [u8]    |        u_int32        |    [u8]    |         |
+-----+-----+-----+-----+------------+-----+-----+-----+-----+------------+---------+
```
### Process
* Check for existing keys
    * Create pub/priv key if server key's do not exist
    * Store key pair in magicant and magicant.pub
    * Check Authorization header for identifier for check against stored pub keys
        * If pub key does not exist for identifier, return 401 Unauthorized
* Obtain nonce from request header
    * If nonce exists, decrypt request using shared secret derived from:
        * Nonce
        * Server Private Key
        * Requester Public Key
    * If nonce does not exist, return 403 Forbidden
* Process Request and obtain unencrypted response
* Generate new nonce for identity
* Generate new secret using:
    * New nonce
    * Server Private Key
    * Request Public Key
* Encrypt Response with new secret

# Closing thoughts
As I was getting to a workable part in this project so that I can interface this with other applications, I began to understand some things I would need to go back and redesign. 

This project does not use the AEAD provided with the `ChaCha20Poly1305` crate implementation. This is absolutely the first thing I want to come back to. At this time, all chunks are encrypted with the same generated nonce, which is, at the time of writing this, against secure practices.

Since this utilizes Asymmetric encryption, performance with encryption is much slower than without. In my performance testing, a 200 MB/s unencrypted download would slow to ~50 MB/s. There are still many usecases I would use this: when security is more important than speed, when requests and responses are intentionally small. This is a known aspect of end-to-end encryption, however I suspect there is another performance loss in integrating this with how actix_web processes packet chunks.