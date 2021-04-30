import socket
import struct
import argparse
import errno
# For encryption
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import PublicFormat, Encoding, load_der_public_key

if __name__ == '__main__':
    # Handle arguments
    ap = argparse.ArgumentParser()
    ap.add_argument("-i", "--host-ip", type=str, required=True,
        help="ip address of the server to connect to")
    ap.add_argument("-p", "--port", type=int, required=True,
        help="port number to connect to")
    args = vars(ap.parse_args())

    # Hard-coded p and g for DH Key exchange (RFC 3526 - group id 14)
    p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
    g = 2
    # print("Using p =", p)
    # print("Using g =", g)

    # Use our p and g with cryptography library
    params_numbers = dh.DHParameterNumbers(p,g)
    parameters = params_numbers.parameters(default_backend())

    # Generate private and public key
    client_private_key = parameters.generate_private_key()
    client_public_key_enc= client_private_key.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    print("Generated Public Key: \n", client_public_key_enc)

    # create socket
    client_socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    host_ip = args["host_ip"]
    port = args["port"]

    try:
        # Initialize Connection
        print("Connecting to server...")
        client_socket.connect((host_ip,port)) # a tuple

        # Receiving size of server's public key and server's public key
        size = client_socket.recv(2)
        server_public_key_enc = client_socket.recv(int.from_bytes(size, "big"))
        print("Size of server's public key: ", int.from_bytes(size, "big"))
        print("Server's public key:\n", server_public_key_enc)

        # Decode server's public key
        server_public_key = load_der_public_key(server_public_key_enc, default_backend())

        # Send size of public key and public key to server
        client_socket.send(len(server_public_key_enc).to_bytes(2, "big") + client_public_key_enc)
        print("Sent client's public key to", host_ip, ":", port)

        # Generate shared key
        shared_key = client_private_key.exchange(server_public_key)
        print("Shared Key:\n", shared_key)

        # Derive Key from shared key
        derived_key = HKDF(algorithm=hashes.SHA256(),length=256,salt=None,info=b'handshake data',).derive(shared_key)
        print("Derived Key:\n", derived_key)


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