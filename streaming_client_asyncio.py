import socket
import cv2
import pickle
import struct
import threading
import argparse
import errno
# For encryption
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import PublicFormat, Encoding, load_der_public_key
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

watching = True

# thread that listens for any input, used to terminate stream loop
def key_capture_thread():
    global watching
    input()
    watching = False
    print("starting exit process")

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

    # Send Message to let server know it's going to send the public key
    # host_socket.send()
    # Send size of public key and public key to remote
    host_socket.send(b"PUBK" + len(host_public_key_enc).to_bytes(2, "big") + host_public_key_enc)
    print("Sent host's public key to", host_ip, ":", port)

    # Generate shared key
    shared_key = host_private_key.exchange(remote_public_key)
    print("Shared Key:\n", shared_key)

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

    # create socket
    client_socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    host_ip = args["host_ip"]
    port = args["port"]

    threading.Thread(target=key_capture_thread, args=(), name='key_capture_thread', daemon=True).start()
    try:
        # Generate new dh key pairs before each connection
        client_private_key, client_public_key_enc = generate_dh_key_pairs()
        # Initialize Connection
        client_socket.connect((host_ip,port)) # a tuple

        client_socket.sendall(b"HELO")
        # === DH KEY EXCHANGE START ===

        shared_key = client_dh_key_exchange(client_socket, client_private_key, client_public_key_enc)
        print("ran DH func")
        data = client_socket.recv(5)
        print(data)
        if data == b"DHFIN":
            print("DH Exchange complete")
        # Derive Key from shared key, length is in byte (32 byte = 256 bit)
        derived_key = HKDF(algorithm=hashes.SHA256(),length=32,salt=None,info=b'handshake data',).derive(shared_key)
        print("Derived Key:\n", derived_key)

        # === DH KEY EXCHANGE END ===

        # initialize data var
        data = b""
        # Specify size as 8 bytes
        payload_size = struct.calcsize("Q")
        while watching:
            client_socket.send(b"READY")
            # Grab packet
            while len(data) < payload_size:
                packet = client_socket.recv(4*1024)
                print("some data received")
                if not packet: break
                data+=packet
            print("# Get packed size of received data, first 8 bytes of packet")
            packed_msg_size = data[:payload_size]
            print(packed_msg_size)
            print("# Get the initial frame data, eveything after the first 8 bytes")
            data = data[payload_size:]
            # Unpack to get real size of expected message
            msg_size = struct.unpack("Q",packed_msg_size)[0]
            # Get the rest of the frame data
            while len(data) < msg_size:
                data += client_socket.recv(4*1024)
            # Store the full frame data
            frame_data = data[:msg_size]
            # Keep the tail data in data variable
            data = data[msg_size:]
            # Deserialize frame data
            frame = pickle.loads(frame_data)
            # Display the images
            cv2.imshow("WATCHING %s STREAM" % (host_ip),frame)
            key = cv2.waitKey(1) & 0xFF
            if key  == ord('q') or not watching:
                print("Leaving the Stream")
                client_socket.sendall(b"LEAVING")
                break
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