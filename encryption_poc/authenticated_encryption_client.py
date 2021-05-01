import socket
import struct
import argparse
import errno
# For encryption
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh, padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import PublicFormat, Encoding, load_der_public_key, load_pem_public_key, load_pem_private_key
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey


# def identification_sheme(client_socket, client_pubkey, client_privkey, server_pubkey):
#     # Client sends HELO message to start Identification process
#     #     Server sends server public key
#     # Client sends client public key
#     #     If server in restricted mode, checks if client public key is in whitelist
#     #     Server sends a signed random message encrypted with clients public key
#     # Client decrypts and verifies signed message. Client trusts this (flawed we need a PKI to allow client to trust server)
#     # Client signs the random message and encrypts this with servers public key, sends that
#     #     Server decrypts and verifies signature and checks the message. If the message is the same then Server can trust client is who they say they are.

# TODO: maybe add tags into encrypt and use in decrypt
def encrypt(key, plaintext, iv):
    # Declare cipher type
    cipher = Cipher(algorithms.AES(key), modes.OFB(iv))
    encryptor = cipher.encryptor()

    # Encrypt
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    return ciphertext

def decrypt(key, ciphertext, iv):
    # Declare cipher type
    cipher = Cipher(algorithms.AES(key), modes.OFB(iv))
    decryptor = cipher.decryptor()

    # Decrypt
    deciphered_text = decryptor.update(ciphertext) + decryptor.finalize()

    return deciphered_text

def sign(private_key, data):
    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    return signature

def verify(public_key, signature, message):
    print("IN VERIFY")
    print("public_key:\n", public_key)
    print("signature:\n", signature)
    print("message:\n", message)
    # Verify signature
    public_key.verify(
        signature,
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

def generate_dh_key_pairs():
    # Hard-coded p and g for DH Key exchange (RFC 3526 - group id 14)
    p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
    g = 2

    # Use our p and g with cryptography library
    params_numbers = dh.DHParameterNumbers(p,g)
    parameters = params_numbers.parameters(default_backend())

    # Generate private and public key
    host_private_key = parameters.generate_private_key()
    host_public_key_enc= host_private_key.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    return (host_private_key, host_public_key_enc)

def client_dh_key_exchange(host_socket, host_private_key, host_public_key_enc):
    # Receiving size of remote's public key and remote's public key
    size = host_socket.recv(2)
    remote_public_key_enc = host_socket.recv(int.from_bytes(size, "big"))
    print("Size of remote's public key: ", int.from_bytes(size, "big"))
    print("Remote's public key:\n", remote_public_key_enc)

    # Decode remote's public key
    remote_public_key = load_der_public_key(remote_public_key_enc, default_backend())

    # Sign A, B, g^x, g^y
    # A = Server's RSA public key
    # B = Client's RSA public key
    server_RSA_public_key = None
    client_RSA_public_key = None

    # print("Opening server_RSA_public_key")
    with open("/home/kali/Documents/Cryptography/project2/secproject_basic_stream_app/env/keys/server/public-key.pem", "rb") as key_file:
        server_RSA_public_key = load_pem_public_key(
            key_file.read()
        )
    # print("server_RSA_public_key:", isinstance(server_RSA_public_key, RSAPublicKey))
    # print(server_RSA_public_key)

    # print("Opening client_RSA_public_key")
    with open("/home/kali/Documents/Cryptography/project2/secproject_basic_stream_app/env/keys/client/client_01/public-key.pem", "rb") as key_file:
        client_RSA_public_key = load_pem_public_key(
            key_file.read()
        )
    # print("client_RSA_public_key:", isinstance(client_RSA_public_key, RSAPublicKey))
    # print(client_RSA_public_key)

    client_RSA_private_key = None
    # print("Opening client_RSA_private_key")
    with open("/home/kali/Documents/Cryptography/project2/secproject_basic_stream_app/env/keys/client/client_01/private-key.pem", "rb") as key_file:
        client_RSA_private_key = load_pem_private_key(
            key_file.read(),
            password=None,
        )
    # print("client_RSA_private_key:", isinstance(client_RSA_private_key, RSAPublicKey))
    # print(client_RSA_private_key)

    # Serialize RSA public keys
    server_RSA_public_key_enc = server_RSA_public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    client_RSA_public_key_enc = client_RSA_public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    print("server_RSA_public_key_enc:\n", server_RSA_public_key_enc)
    print("client_RSA_public_key_enc:\n", client_RSA_public_key_enc)
    
    # Sign
    message = server_RSA_public_key_enc + client_RSA_public_key_enc + remote_public_key_enc + host_public_key_enc
    message_signature = sign(client_RSA_private_key, message)
    print("Message signed")

    # Send size of public key, public key, size of signature, signature to remote
    host_socket.send(
        len(host_public_key_enc).to_bytes(2, "big") + 
        host_public_key_enc +
        len(message_signature).to_bytes(2, "big") + 
        message_signature
        )
    print("Sent host's public key and signature to", host_ip, ":", port)

    # Receiving size of remote's signature and remote's signature
    size = client_socket.recv(2)
    remote_sigature = client_socket.recv(int.from_bytes(size, "big"))
    print("Size of remote's signature: ", int.from_bytes(size, "big"))
    print("Remote's signature:\n", remote_sigature)

    # Verify message
    intended_message = server_RSA_public_key_enc + host_public_key_enc
    verify(server_RSA_public_key, remote_sigature, intended_message)
    print("Message verified")

    # Generate shared key
    shared_key = host_private_key.exchange(remote_public_key)
    print("Shared Key:\n", shared_key)

    # Derive Key from shared key, length is in byte (32 byte = 256 bit)
    derived_key = HKDF(algorithm=hashes.SHA256(),length=32,salt=None,info=b'handshake data',).derive(shared_key)
    print("Derived Key:\n", derived_key)

    return shared_key

def receive_and_decrypt_AES_OFB_message(host_socket, derived_key, derived_iv):
    size = host_socket.recv(2)
    ciphertext = host_socket.recv(int.from_bytes(size, "big"))
    deciphered_text = decrypt(derived_key, ciphertext, derived_iv)
    return deciphered_text

if __name__ == '__main__':
    # Handle arguments
    ap = argparse.ArgumentParser()
    ap.add_argument("-i", "--host-ip", type=str, required=True,
        help="ip address of the server to connect to")
    ap.add_argument("-p", "--port", type=int, required=True,
        help="port number to connect to")
    args = vars(ap.parse_args())

    # Hard-coded p and g for DH Key exchange (RFC 3526 - group id 14)
    # p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
    # g = 2
    # print("Using p =", p)
    # print("Using g =", g)

    client_private_key, client_public_key_enc = generate_dh_key_pairs()
    print("Generated Public Key: \n", client_public_key_enc)

    # create socket
    client_socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    host_ip = args["host_ip"]
    port = args["port"]

    try:
        # Initialize Connection
        print("Connecting to server...")
        client_socket.connect((host_ip,port)) # a tuple

        # === DH KEY EXCHANGE START ===

        shared_key = client_dh_key_exchange(client_socket, client_private_key, client_public_key_enc)

        # Derive Key from shared key, length is in byte (32 byte = 256 bit)
        derived_key = HKDF(algorithm=hashes.SHA256(),length=32,salt=None,info=b'handshake data',).derive(shared_key)
        print("Derived Key:\n", derived_key)

        # === DH KEY EXCHANGE END ===

        # === AES with OFB START ===
        # The above 32 byte derived_key will be used as the key.
        # A 16 byte IV will be derived so both client and server has the same IV.
        derived_iv = HKDF(algorithm=hashes.SHA256(),length=16,salt=None,info=b'aes ofb iv',).derive(shared_key)
        print("Derived IV:\n", derived_iv)

        # Receive data and decrypt
        i = 0
        while i<2:
            deciphered_text = receive_and_decrypt_AES_OFB_message(client_socket, derived_key, derived_iv)
            print("deciphered_text:", len(deciphered_text), "\n", deciphered_text)
            i += 1

        # === AES with OFB END ===





    except struct.error as e:
        # Handle case when server stops sending data, i.e. stream ended
        if len(packed_msg_size) == 0:
            print("Stream has ended")
        else:
            raise e
    except ConnectionResetError as e:
        if e.errno == errno.ECONNRESET:
            print("Stream has ended")
        else:
            raise e
    finally:
        client_socket.close()