# Process command line arguments
import argparse
# Needed for network communication
import socket
import struct
# For encryption
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh, padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import PublicFormat, Encoding, load_der_public_key, load_pem_public_key, load_pem_private_key
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# # Modular Exponentiation: https://crypto.stackexchange.com/questions/75408/efficient-function-algorithm-method-to-do-modular-exponentiation
# # Not used since cryptography library did all the DH work
# def fast_power(base, power, mod):
#     result = 1
#     while power > 0:
#         # If power is odd
#         if power % 2 == 1:
#             result = (result * base) % mod

#         # Divide the power by 2
#         power = power // 2
#         # Multiply base to itself
#         base = (base * base) % mod

#     return result

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

def generate_ecdh_key_pairs():
    host_private_key = ec.generate_private_key(
        ec.SECP384R1()
    )
    host_public_key_enc = host_private_key.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    return (host_private_key, host_public_key_enc)

def server_dh_key_exchange(client_socket, host_private_key, host_public_key_enc):
    # Send size of public key and public key to remote
    client_socket.send(len(host_public_key_enc).to_bytes(2, "big") + host_public_key_enc)
    print("Sent host's public key to ", caddr, ":", cport)

    # Receiving size of remote's public key and remote's public key
    size = client_socket.recv(2)
    remote_public_key_enc = client_socket.recv(int.from_bytes(size, "big"))
    print("Size of remote's public key: ", int.from_bytes(size, "big"))
    print("Remote's public key:\n", remote_public_key_enc)

    # Receiving size of remote's signature and remote's signature
    size = client_socket.recv(2)
    remote_sigature = client_socket.recv(int.from_bytes(size, "big"))
    print("Size of remote's signature: ", int.from_bytes(size, "big"))
    print("Remote's signature:\n", remote_sigature)

    # Decode remote's public key
    remote_public_key = load_der_public_key(remote_public_key_enc, default_backend())

    # Build message to be verified 
    # message = A, B, g^x, g^y
    # A = Server's RSA public key
    # B = Client's RSA public key
    server_RSA_public_key = None
    client_RSA_public_key = None

    with open("/home/kali/Documents/Cryptography/project2/secproject_basic_stream_app/env/keys/server/public-key.pem", "rb") as key_file:
        server_RSA_public_key = load_pem_public_key(
            key_file.read()
        )

    with open("/home/kali/Documents/Cryptography/project2/secproject_basic_stream_app/env/keys/client/client_01/public-key.pem", "rb") as key_file:
        client_RSA_public_key = load_pem_public_key(
            key_file.read()
        )

    server_RSA_private_key = None
    with open("/home/kali/Documents/Cryptography/project2/secproject_basic_stream_app/env/keys/server/private-key.pem", "rb") as key_file:
        server_RSA_private_key = load_pem_private_key(
            key_file.read(),
            password=None,
        )

    # Serialize RSA public keys
    # print("Serializing both RSA public keys")
    server_RSA_public_key_enc = server_RSA_public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    client_RSA_public_key_enc = client_RSA_public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    print("server_RSA_public_key_enc:\n", server_RSA_public_key_enc)
    print("client_RSA_public_key_enc:\n", client_RSA_public_key_enc)

    # Verify message
    intended_message = server_RSA_public_key_enc + client_RSA_public_key_enc + host_public_key_enc + remote_public_key_enc
    verify(client_RSA_public_key, remote_sigature, intended_message)
    print("Message verified")

    # Creating signature for Sig(A, g^y)
    # A = Server's RSA public key
    host_message = server_RSA_public_key_enc + remote_public_key_enc
    host_signature = sign(server_RSA_private_key, host_message)

    # Send size of host_signature, host_signature to remote
    client_socket.send(
        len(host_signature).to_bytes(2, "big") + 
        host_signature
        )
    print("Sent host's signature to", caddr, ":", cport)

    # Generate shared key
    # DH shared key
    shared_key = host_private_key.exchange(remote_public_key)
    # ECDH shared key
    #shared_key = host_private_key.exchange(ec.ECDH(), remote_public_key)
    return shared_key

def encrypt_and_send_AES_OFB_message(client_socket, plaintext, key, iv):
    ciphertext = encrypt(key, plaintext, iv)
    client_socket.send(len(ciphertext).to_bytes(2, "big") + ciphertext)


if __name__ == '__main__':
    # Handle arguments
    ap = argparse.ArgumentParser()
    ap.add_argument("-i", "--host-ip", type=str, required=True,
        help="ip address of the device")
    ap.add_argument("-p", "--port", type=int, required=True,
        help="ephemeral port number of the server (1024 to 65535)")
    args = vars(ap.parse_args())

    # Hard-coded p and g for DH Key exchange (RFC 3526 - group id 14)
    # p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
    # g = 2
    # print("Using p =", p)
    # print("Using g =", g)

    # # Use our p and g with cryptography library
    # params_numbers = dh.DHParameterNumbers(p,g)
    # parameters = params_numbers.parameters(default_backend())

    # # Generate private and public key
    # server_private_key = parameters.generate_private_key()
    # server_public_key_enc= server_private_key.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    server_private_key, server_public_key_enc = generate_dh_key_pairs()
    # server_public_key = load_der_public_key(server_public_key_enc, default_backend())
    # shared_key = server_private_key.exchange(server_public_key)
    print("Generated Public Key: \n", server_public_key_enc)
    # print(str(shared_key))

    # quit()

    print("Setting up server...")
    # Socket Create
    server_socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    host_ip = args["host_ip"]
    port = args["port"]
    socket_address = (host_ip,port)

    # Socket Bind
    server_socket.bind(socket_address)

    # Socket Listen
    server_socket.listen(5)
    print("LISTENING AT:",socket_address)

    try: 
        print("waiting for connection - before accept")
        client_socket,(caddr, cport) = server_socket.accept()

        # === DH KEY EXCHANGE START ===

        shared_key = server_dh_key_exchange(client_socket, server_private_key, server_public_key_enc)
        print("Shared Key:\n", shared_key)

        # Derive Key from shared key, length is in byte (32 byte = 256 bit)
        derived_key = HKDF(algorithm=hashes.SHA256(),length=32,salt=None,info=b'handshake data',).derive(shared_key)
        print("Derived Key:\n", derived_key)

        # === DH KEY EXCHANGE END ===

        # === AES with OFB START ===
        # The above 32 byte derived_key will be used as the key.
        # A 16 byte IV will be derived so both client and server has the same IV.
        derived_iv = HKDF(algorithm=hashes.SHA256(),length=16,salt=None,info=b'aes ofb iv',).derive(shared_key)
        print("Derived IV:\n", derived_iv)
        
        # Encrypt
        plaintext1 = 'A'*256
        plaintext2 = 'B'*2048 * 2
        encrypt_and_send_AES_OFB_message(client_socket, plaintext1.encode(), derived_key, derived_iv)
        encrypt_and_send_AES_OFB_message(client_socket, plaintext2.encode(), derived_key, derived_iv)
        # ciphertext1 = encrypt(derived_key, plaintext1.encode(), derived_iv)
        # ciphertext2 = encrypt(derived_key, plaintext2.encode(), derived_iv)
        # print("ciphertext1:", len(ciphertext1), "\n", ciphertext1)
        # print("ciphertext2:", len(ciphertext2), "\n", ciphertext2)

        # Send ciphertexts to client
        # client_socket.send(len(ciphertext1).to_bytes(2, "big") + ciphertext1)
        # client_socket.send(len(ciphertext2).to_bytes(2, "big") + ciphertext2)

        # === AES with OFB END ===

                    
    finally:
        print("Shutting Down Server")
        try:
            server_socket.shutdown(socket.SHUT_RDWR)
        except OSError as e:
            if e.strerror == "Socket is not connected":
                print("No connections found, proceeding to close socket.")
            else:
                raise e
        finally:
            print("Closing Server Socket")
            server_socket.close()