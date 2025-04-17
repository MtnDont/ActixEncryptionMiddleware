# Encryption Middleware

This middleware assumes you have safely exchanged keys with the server. The Authorization identifier matches the name of the key.

### HTTP Request Header
```
Content-Type: <CONTENT-TYPE>
Magicant-Nonce: <NONCE>
Authorization: Basic <BASE64-IDENTIFIER>
```
### HTTP Response Header
```
Content-Type: <CONTENT-TYPE>
Magicant-Nonce: <NONCE>
```
### Encrypted Body Structure
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

# File Request (/pf)
### HTTP Header
```
Content-Type: applicaiton/json
```
### JSON Content
```
{
    "path": "<PATH>",
    "filename": "<FILENAME>"
}
```