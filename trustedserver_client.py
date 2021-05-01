import socket
import struct
import argparse
import errno
# Cryptography
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import PublicFormat, Encoding
from cryptography.hazmat.primitives import hashes


def lookupIP(client_socket, public_key):
    client_socket.send(b'1')
    client_socket.send(len(public_key).to_bytes(2, "big") + public_key)
    output = client_socket.recv(1024)

    return output

def registerPublicKey(client_socket, public_key, private_key):
    client_socket.send(b'0')
    signed_public_key = sign(private_key, public_key)
    client_socket.send(len(public_key).to_bytes(2, "big") + public_key)
    client_socket.send(len(signed_public_key).to_bytes(2, "big") + signed_public_key)
    output = client_socket.recv(1024)

    return output

def generateRSAKey():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    return private_key

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


if __name__ == '__main__':
    # Handle arguments
    ap = argparse.ArgumentParser()
    ap.add_argument("-i", "--host-ip", type=str, required=True,
        help="ip address of the server to connect to")
    ap.add_argument("-p", "--port", type=int, required=True,
        help="port number to connect to")
    args = vars(ap.parse_args())

    # create socket
    client_socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    host_ip = args["host_ip"]
    port = args["port"]

    # Create private key and public key
    client_private_key = generateRSAKey()
    client_public_key = client_private_key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)

    try:
        # Initialize Connection
        client_socket.connect((host_ip,port)) # a tuple

        msgCode = 0

        if msgCode == 1:
            # Look up IP for public key
            ip = lookupIP(client_socket, client_public_key)
            print("ip:", ip)

        elif msgCode == 0:
            # # Register public key
            response = registerPublicKey(client_socket, client_public_key, client_private_key)
            print("response:", response)
            client_socket.close()

        else: 
            print("This msgCode currently not implemented.")

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