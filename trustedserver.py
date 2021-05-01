# Need threading for multiple clients and a way to terminate gracefully
import threading
# Process command line arguments
import argparse
# Needed for network communication
import socket
# Cryptography (signature)
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import PublicFormat, Encoding, load_pem_public_key
from cryptography.exceptions import InvalidSignature

# Globals for handling the frames
lock = threading.Lock()
publicKeyMapping = {}

def new_client(client_socket, caddr):
    global lock, publicKeyMapping
    if client_socket:
        try:
            # msgCode 0 = REGISTER, 1 = READ, more later if needed...
            msgCode = client_socket.recv(1)
            
            # Register
            if msgCode == b'0':
                # print("IN REGISTER")
                # Receive client's public key and signed public key
                clientPublicKeySize = client_socket.recv(2)
                clientPublicKey = client_socket.recv(int.from_bytes(clientPublicKeySize, "big")) # Serialized
                clientPublicKeyDeserialized = load_pem_public_key(clientPublicKey, default_backend())
                clientPublicKeySignedSize = client_socket.recv(2)
                clientPublicKeySigned = client_socket.recv(int.from_bytes(clientPublicKeySignedSize, "big"))

                # Verify signature
                clientPublicKeyDeserialized.verify(
                    clientPublicKeySigned,
                    clientPublicKey,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )

                with lock:
                    # Add mapping into dict
                    publicKeyMapping[clientPublicKey] = caddr

                # Send Complete message
                client_socket.send(b'REGISTER COMPLETE')
                print("New public key is registered")

                # Print publicKeyMapping
                print("=== Current Mapping ====")
                with lock:
                    for k,v in publicKeyMapping.items():
                        print(v, '\n', k)
                print("========================")

            # Read
            elif msgCode == b'1':
                # print("IN READ")
                # Receive client's public key to be looked up
                clientPublicKeySize = client_socket.recv(2)
                clientPublicKey = client_socket.recv(int.from_bytes(clientPublicKeySize, "big"))

                # print("clientPublicKeySize:", clientPublicKeySize)
                # print("Looking up:\n", clientPublicKey)
                with lock:
                    # Lookup IP
                    if clientPublicKey in publicKeyMapping:
                        ip = publicKeyMapping[clientPublicKey]

                        # Send IP
                        client_socket.send(ip.encode())
                    else:
                        client_socket.send(b'UNREGISTERED')

            else:
                client_socket.send(b'INVALID MESSAGE CODE')
            

        except InvalidSignature as e:
            print("Verification failed. Closing connection.")
            raise e

        finally:
            # print("A connection has closed")
            client_socket.close()


if __name__ == '__main__':
    # Handle arguments
    ap = argparse.ArgumentParser()
    ap.add_argument("-i", "--host-ip", type=str, required=True,
        help="ip address of the device")
    ap.add_argument("-p", "--port", type=int, required=True,
        help="ephemeral port number of the server (1024 to 65535)")
    args = vars(ap.parse_args())

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

    threads = []

    try: 
        while True:
            print("waiting for connection - before accept")
            client_socket,(caddr, cport) = server_socket.accept()
            if client_socket:
                print("waiting for connection - after accept")
                print('GOT CONNECTION FROM: %s:%s' % (caddr, cport))
                connThread = threading.Thread(target=new_client, args=(client_socket,caddr,))
                threads.append(connThread)
                connThread.start()

    except KeyboardInterrupt as e:
        print("Shutdown may leave some temp files in local directory")
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
