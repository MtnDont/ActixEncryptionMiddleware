from base64 import b64encode
from blake3 import blake3
from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Protocol.DH import key_agreement
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from nacl.secret import SecretBox
from nacl.bindings import crypto_aead_xchacha20poly1305_ietf_decrypt
import sys

def create_req():
    # Create plaintext
    plain = b'{"path":"path/path2","filename":"test.png"}'

    # Create nonce for cipher
    nonce_str = b'testingtestingtestingtes'

    # Username
    user = "test"

    # Store client private key and server public key in memory
    cli_priv_key = b""
    serv_pub_key = b""
    with open(f".magicant/{user}", "rb") as f:
        cli_priv_key = x25519.X25519PrivateKey.from_private_bytes(f.read(32))
    with open(".magicant/key.pub", "rb") as f:
        serv_pub_key = x25519.X25519PublicKey.from_public_bytes(f.read(32))

    # Diffie–Hellman key exchange
    df_der_key = cli_priv_key.exchange(serv_pub_key)

    # Create hashed key+nonce
    # MAC = Message authentication code
    mac = blake3(
        nonce_str,
        key=df_der_key
    ).digest()

    # Create cipher to iterate over data
    cipher = ChaCha20_Poly1305.new(
        key=mac,
        nonce=nonce_str
    )

    # Encrypt the text, get tag
    encrypted_text, tag = cipher.encrypt_and_digest(plain)

    print(f"Text size: {sys.getsizeof(encrypted_text)}")
    print(f"Tag size: {sys.getsizeof(tag)}")

    # base64 Encode user and nonce string
    b64_user_encode = b64encode(str.encode(user)).decode('utf-8')
    b64_nonce_encode = b64encode(str.encode(nonce_str)).decode('utf-8')

    # POST 192.168.50.70:25506/pf
    with open('request-data.bin', 'wb') as f:
        f.write(encrypted_text + tag)
        print(f"curl -v -X POST 192.168.50.70:25506/pf -H 'Content-Type: application/json' -H 'magicant-nonce: {b64_nonce_encode}' -H 'Authorization: Basic {b64_user_encode}' --data-binary '@request-data.bin' --output out.bin")

def decrypt():
    # Username
    user = "test"

    nonce = b'\x62\xC7\x30\xC6\x53\x78\xE1\xF2\xC4\x28\x63\xB4\xF7\xD6\x3D\xEA\xF7\x74\x03\x0E\x9C\x79\xA3\x7B'

    # Store client private key and server public key in memory
    cli_priv_key = b""
    serv_pub_key = b""
    with open(f".magicant/{user}", "rb") as f:
        cli_priv_key = x25519.X25519PrivateKey.from_private_bytes(f.read(32))
    with open(".magicant/key.pub", "rb") as f:
        serv_pub_key = x25519.X25519PublicKey.from_public_bytes(f.read(32))

    # Diffie–Hellman key exchange
    df_der_key = cli_priv_key.exchange(serv_pub_key)

    # Create hashed key+nonce
    # MAC = Message authentication code
    mac = blake3(
        nonce,
        key=df_der_key
    ).digest()

    # Structure of encrypted ciphertext file
    # +-------------------+--------+-------------------+--------+-----+
    # | 1st c_text len    | c_text | 2nd c_text len    | c_text | ... |
    # +-------------------+--------+-------------------+--------+-----+
    # |    u_int32        |        |    u_int32        |
    # +----+----+----+----+        +----+----+----+----+
    with open('out.bin', 'rb') as enc_response:
        with open('decrypted_out.bin', 'wb') as decrypted_f:
            ctext_len = int.from_bytes(enc_response.read(4), "big")
            print(f"ctext_len: {ctext_len}")
            ciphertext = enc_response.read(ctext_len)

            while ciphertext:
                if len(ciphertext) != ctext_len:
                    raise ValueError("corrupted or incomplete chunk")
                
                decrypted_f.write(
                    crypto_aead_xchacha20poly1305_ietf_decrypt(
                        ciphertext,
                        aad=None,
                        nonce=nonce,
                        key=mac
                    )
                )

                ctext_len = int.from_bytes(enc_response.read(4), "big")
                print(f"ctext_len: {ctext_len}")
                ciphertext = enc_response.read(ctext_len)

if __name__ == '__main__':
    if len(sys.argv) > 1:
        decrypt()
    else:
        create_req()