import socket
import cv2
import pickle
import struct
import threading
import argparse
import errno
import time
# For encryption
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import dh, rsa, padding, ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import PublicFormat, Encoding, load_der_public_key, load_pem_public_key, load_pem_private_key
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.exceptions import InvalidSignature

watching = True
watch_char = {
    0: "/",
    1: "-",
    2: "|",
    3: "\\",
    4: "|",
}
disable_ecdh = False

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

def generate_ecdh_key_pairs():
    host_private_key = ec.generate_private_key(
        ec.SECP384R1()
    )
    host_public_key_enc = host_private_key.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    return (host_private_key, host_public_key_enc)

def client_dh_key_exchange(host_socket, host_private_key, host_public_key_enc, serialized_RSA_server_public_key, serialized_RSA_client_public_key, RSA_client_private_key):
    global disable_ecdh
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
    message_to_be_signed = serialized_RSA_server_public_key + serialized_RSA_client_public_key + remote_public_key_enc + host_public_key_enc
    message_signature = sign(RSA_client_private_key, message_to_be_signed)
    host_socket.send(b"PUBK" +
                    len(host_public_key_enc).to_bytes(2, "big") +
                    host_public_key_enc +
                    len(message_signature).to_bytes(2, "big") +
                    message_signature)
    print("Sent host's public key to", host_ip, ":", port)
    # Get server's signature
    size = host_socket.recv(2)
    remote_signature = host_socket.recv(int.from_bytes(size, "big"))
    # Verify server's signature
    intended_message = serialized_RSA_server_public_key + host_public_key_enc
    verify(load_pem_public_key(serialized_RSA_server_public_key), remote_signature, intended_message)

    # Generate shared key
    if disable_ecdh:
        shared_key = host_private_key.exchange(remote_public_key)
    else:
        shared_key = host_private_key.exchange(ec.ECDH(), remote_public_key)
    print("Shared Key:\n", shared_key)

    return shared_key

def receive_and_decrypt_AES_OFB_message(host_socket, derived_key, derived_iv):
    size = host_socket.recv(2)
    ciphertext = host_socket.recv(int.from_bytes(size, "big"))
    deciphered_text = decrypt(derived_key, ciphertext, derived_iv)
    return deciphered_text

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




if __name__ == '__main__':
    # Handle arguments
    ap = argparse.ArgumentParser()
    ap.add_argument("-i", "--host-ip", type=str, required=False,
        help="ip address of the server to connect to", default='127.0.0.1')
    ap.add_argument("-p", "--port", type=int, required=False,
        help="port number to connect to", default=9898)
    ap.add_argument("--pki-host-ip", type=str, required=False,
        help="ip address of the PKI server to connect to", default='127.0.0.1')
    ap.add_argument("--pki-port", type=int, required=False,
        help="PKI port number to connect to", default=7777)
    ap.add_argument("--rsa-pub-key", type=str, required=False,
        help="Path to RSA PEM public key", default='env/keys/client/client_01/public-key.pem')
    ap.add_argument("--rsa-priv-key", type=str, required=False,
        help="Path to RSA PEM private key", default='env/keys/client/client_01/private-key.pem')
    ap.add_argument("--disable-ecdh", type=bool, required=False,
        help="Disable Elliptic Curve key generation for Diffie-Hellman Key Exchange, needs to match server", default=False)
    args = vars(ap.parse_args())

    disable_ecdh = args["disable_ecdh"]
    RSA_client_public_key = None
    RSA_client_private_key = None
    with open(args["rsa_pub_key"], "rb") as key_file:
        RSA_client_public_key = load_pem_public_key(
            key_file.read()
        )
    with open(args["rsa_priv_key"], "rb") as key_file:
        RSA_client_private_key = load_pem_private_key(
            key_file.read(),
            password=None,
        )

    # Serialize keys
    serialized_RSA_client_public_key = RSA_client_public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)

    # ## --------- PKI Register Pub Keys START-----------##
    # pki_client_socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    # pki_host_ip = args["pki_host_ip"]
    # pki_port = args["pki_port"]
    # pki_client_socket.connect((pki_host_ip,pki_port))
    # response = registerPublicKey(pki_client_socket, serialized_RSA_client_public_key, RSA_client_private_key)
    # print("response:", response)
    # pki_client_socket.close()
    # ## --------- PKI Register Pub Keys END  -----------##

    # create socket
    client_socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    host_ip = args["host_ip"]
    port = args["port"]
    abort = False
    threading.Thread(target=key_capture_thread, args=(), name='key_capture_thread', daemon=True).start()
    frames_processed_counter = 0
    try:

        # Generate new dh key pairs before each connection
        if disable_ecdh:
            client_private_key, client_public_key_enc = generate_dh_key_pairs()
        else:
            client_private_key, client_public_key_enc = generate_ecdh_key_pairs()
        # Initialize Connection
        client_socket.connect((host_ip,port)) # a tuple
        serialized_RSA_server_public_key = None
        initial_message = b"HELO" + len(serialized_RSA_client_public_key).to_bytes(2, "big") + serialized_RSA_client_public_key
        client_socket.sendall(initial_message)
        # === GET RSA PUBLIC KEY START ===
        data = client_socket.recv(4)
        if data == b"HELO":
            size = client_socket.recv(2)
            serialized_RSA_server_public_key = client_socket.recv(int.from_bytes(size, "big"))
        elif data == b"RJKT":
            print("Stream is running in restricted mode, only whitelisted users allowed")
            abort = True
            exit()
        else:
            abort = True
        # === GET RSA PUBLIC KEY END ===


        # === DH KEY EXCHANGE START ===
        client_socket.sendall(b"DHINI")
        shared_key = client_dh_key_exchange(client_socket,
                                            client_private_key,
                                            client_public_key_enc,
                                            serialized_RSA_server_public_key,
                                            serialized_RSA_client_public_key,
                                            RSA_client_private_key)
        print("ran DH func")
        data = client_socket.recv(5)
        print(data)
        if data == b"DHFIN":
            print("DH Exchange complete")
        # === DH KEY EXCHANGE END ===

        # Derive Key from shared key, length is in byte (32 byte = 256 bit)
        derived_key = HKDF(algorithm=hashes.SHA256(),length=32,salt=None,info=b'handshake data',).derive(shared_key)
        print("Derived Key:\n", derived_key)

        # A 16 byte IV will be derived so both client and server has the same IV.
        derived_iv = HKDF(algorithm=hashes.SHA256(),length=16,salt=None,info=b'aes ofb iv',).derive(shared_key)
        print("Derived IV:\n", derived_iv)

        # HMAC key
        derived_hmac_key = HKDF(algorithm=hashes.SHA256(),length=32,salt=None,info=b'mac',).derive(shared_key)

        # Session ID
        derived_session_id = HKDF(algorithm=hashes.SHA256(),length=32,salt=None,info=b'session id',).derive(shared_key)

        component_id_tracker = 0
        # initialize data var
        data = b""
        # Specify size as 8 bytes
        payload_size = struct.calcsize("Q")
        smud = 0
        stracker = 0
        start_time = time.time()
        while watching:
            client_socket.send(b"READY")
            # Grab packet
            while len(data) < payload_size:
                packet = client_socket.recv(4*1024)
                if smud < 200:
                    if smud % 20 == 0:
                        time_passed = time.time() - start_time
                        avg_fps = frames_processed_counter / time_passed
                        avg_fps = "{0:.2f}".format(avg_fps)
                        print(f"{watch_char[stracker]} watching stream {watch_char[stracker]} AVG FPS: {avg_fps}", end="\r")
                        stracker += 1
                        if stracker > 4:
                            stracker = 0
                    smud += 1
                else:
                    smud = 0
                if not packet: break
                data+=packet
            # print("# Get packed size of received data, first 8 bytes of packet")
            # TODO check if these are  len 0
            recv_hmac_sig = data[:32]
            if len(recv_hmac_sig) != 32:
                continue
            remote_session_id = data[32:32+32]
            if len(remote_session_id) != 32:
                continue
            remote_bytes_component_id = data[32+32:32+32+4]
            if len(remote_bytes_component_id) != 4:
                continue
            packed_msg_size = data[32+32+4:32+32+4+payload_size]
            if len(packed_msg_size) !=  payload_size:
                continue
            # print(packed_msg_size)
            # print("# Get the initial frame data, eveything after the first 8 bytes")
            data = data[32+32+4+payload_size:]
            # Unpack to get real size of expected message
            msg_size = struct.unpack("Q",packed_msg_size)[0]
            # if msg_size > 1536165:

            # Get the rest of the frame data
            while (len(data) < msg_size) and (len(data) < 1536165):
                data += client_socket.recv(4*1024)
            # Store the full frame data
            frame_data = data[:msg_size]

            ## Verification
            # Verify HMAC
            recv_message = remote_session_id + remote_bytes_component_id + packed_msg_size + frame_data
            h = hmac.HMAC(derived_hmac_key, hashes.SHA256())
            h.update(recv_message)
            try:
                h.verify(recv_hmac_sig)
            except InvalidSignature as e:
                continue

            # Verify session id matches
            if derived_session_id != remote_session_id:
                continue

            # Verify component id increased
            remote_int_component_id = int.from_bytes(remote_bytes_component_id, "big")
            if remote_int_component_id <= component_id_tracker:
                continue
            else:
                component_id_tracker = remote_int_component_id

            # Decrypt data
            frame_data = decrypt(derived_key, frame_data, derived_iv)
            # Keep the tail data in data variable
            data = data[msg_size:]
            # Deserialize frame data
            frame = pickle.loads(frame_data)
            # Display the images
            cv2.imshow("WATCHING %s STREAM" % (host_ip),frame)
            key = cv2.waitKey(1) & 0xFF
            if key  == ord('q') or not watching:
                print("\nLeaving the Stream")
                client_socket.sendall(b"LEAVING")
                break
            frames_processed_counter += 1
    except struct.error as e:
        # Handle case when server stops sending data, i.e. stream ended
        if len(packed_msg_size) == 0:
            print("\nStream has ended")
        else:
            raise e
    except ConnectionResetError as e:
        if e.errno == errno.ECONNRESET:
            print("\nStream has ended")
        else:
            raise e
    except BrokenPipeError as e:
        if e.errno == errno.EPIPE:
            print("\nStream may have ended, or connection dropped.")
        else:
            raise e
    finally:
        client_socket.close()