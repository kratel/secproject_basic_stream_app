# Process command line arguments
import argparse
# Needed for network communication
import socket
import struct
# For encryption
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import PublicFormat, Encoding, load_der_public_key

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


if __name__ == '__main__':
    # Handle arguments
    ap = argparse.ArgumentParser()
    ap.add_argument("-i", "--host-ip", type=str, required=True,
        help="ip address of the device")
    ap.add_argument("-p", "--port", type=int, required=True,
        help="ephemeral port number of the server (1024 to 65535)")
    args = vars(ap.parse_args())

    # Hard-coded p and g for DH Key exchange (RFC 3526 - group id 14)
    p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
    g = 2
    print("Using p =", p)
    print("Using g =", g)

    # Use our p and g with cryptography library
    params_numbers = dh.DHParameterNumbers(p,g)
    parameters = params_numbers.parameters(default_backend())

    # Generate private and public key
    server_private_key = parameters.generate_private_key()
    server_public_key_enc= server_private_key.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
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

        # Send size of public key and public key to client
        client_socket.send(len(server_public_key_enc).to_bytes(2, "big") + server_public_key_enc)
        print("Sent server's public key to ", caddr, ":", cport)

        # Receiving size of client's public key and client's public key
        size = client_socket.recv(2)
        client_public_key_enc = client_socket.recv(int.from_bytes(size, "big"))
        print("Size of client's public key: ", int.from_bytes(size, "big"))
        print("Client's public key:\n", client_public_key_enc)

        # Decode client's public key
        client_public_key = load_der_public_key(client_public_key_enc, default_backend())

        # Generate shared key
        shared_key = server_private_key.exchange(client_public_key)
        print("Shared Key:\n", shared_key)

        # Derive Key from shared key
        derived_key = HKDF(algorithm=hashes.SHA256(),length=256,salt=None,info=b'handshake data',).derive(shared_key)
        print("Derived Key:\n", derived_key)

                    
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