# Need threading for multiple clients and a way to terminate gracefully
import threading
# Process command line arguments
import argparse
# Stamp the frames with a timestamp
import datetime
# May need for sleep
import time
# Necessary to process images with openCV
import numpy as np
import pyautogui
import imutils
import cv2
from PIL import UnidentifiedImageError, Image, ImageFile
import os
# Needed for network communication
import socket
import pickle
import struct
# Needed to handle non-blocking server socket
import select
import queue
# Needed to handle async calls
import asyncio
# For encryption
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh, rsa, padding, ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import PublicFormat, Encoding, load_der_public_key, load_pem_public_key, load_pem_private_key
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

ImageFile.LOAD_TRUNCATED_IMAGES = True
# Globals for handling the frames
outputFrame = None
lock = threading.Lock()
stream = True
read_list = []
write_list = []
message_queues = {}
dh_keyexchanges = {}
client_derived_keys_ivs = {}
p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
g = 2
serialized_RSA_server_public_key = None
RSA_server_private_key = None
disable_ecdh = False
loop = None

# thread that listens for any input, used to terminate stream loop
# def key_capture_thread(server_socket):
#     global stream
#     input()
#     stream = False
#     print("starting exit process")

def capture_frames():
    global outputFrame, lock, stream, message_queues
    # threading.Thread(target=key_capture_thread, args=(), name='key_capture_thread', daemon=True).start()
    try:
        # while not event.is_set():
        while stream:
            ##
            # im = Image.open('.screenshot2021-0501_20-10-04-094593.png')
            # im.load()
            ##
            # Grab a screenshot
            frame = pyautogui.screenshot()
            # Convert it cv2 color format and np array
            frame = cv2.cvtColor(np.array(frame), cv2.COLOR_RGB2BGR)
            # Resize so we send consistent amount of data
            frame = imutils.resize(frame, width=800)

            # Stamp Frame with current time.
            timestamp = datetime.datetime.now()
            cv2.putText(frame, timestamp.strftime(
                "%A %d %B %Y %I:%M:%S%p"), (10, frame.shape[0] - 10),
                cv2.FONT_HERSHEY_SIMPLEX, 0.35, (0, 0, 255), 1)

            with lock:
                outputFrame = frame.copy()
                # for sq in message_queues:
                #     serializedFrame = pickle.dumps(outputFrame)
                #     message = struct.pack("Q",len(serializedFrame))+serializedFrame
                #     message_queues[s].put(message)
                # cv2.imshow("RECEIVING VIDEO",outputFrame)
                # cv2.waitKey()

            time.sleep(0.1)
            # print("captured a screenshot")
            # print(stream)
    except UnidentifiedImageError as e:
        quoted_filename = e.args[0].split()[4]
        filename = quoted_filename.strip("'")
        if os.path.exists(filename):
            os.remove(filename)
            print("Deleted leftover temp image file")
    except OSError as e:
        if e.errno == 2:
            # Temp file was not written to disk
            pass
        else:
            raise e


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
    global p, g

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

# def server_dh_key_exchange(reader, writer, host_private_key, host_public_key_enc):
#     # Send size of public key and public key to remote
#     client_socket.send(len(host_public_key_enc).to_bytes(2, "big") + host_public_key_enc)
#     print("Sent host's public key to ", caddr, ":", cport)

#     # Receiving size of remote's public key and remote's public key
#     size = client_socket.recv(2)
#     remote_public_key_enc = client_socket.recv(int.from_bytes(size, "big"))
#     print("Size of remote's public key: ", int.from_bytes(size, "big"))
#     print("Remote's public key:\n", remote_public_key_enc)

#     # Decode remote's public key
#     remote_public_key = load_der_public_key(remote_public_key_enc, default_backend())

#     # Generate shared key
#     shared_key = host_private_key.exchange(remote_public_key)
#     return shared_key

def encrypt_and_send_AES_OFB_message(client_socket, plaintext, key, iv):
    ciphertext = encrypt(key, plaintext, iv)
    client_socket.send(len(ciphertext).to_bytes(2, "big") + ciphertext)

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

async def new_client(reader, writer):
    global lock, stream, outputFrame, serialized_RSA_server_public_key, RSA_server_private_key, disable_ecdh, loop
    try:
        # if client_socket:
            # vid = cv2.VideoCapture(0)
            # global outputFrame, lock
        ## --------- DH Key EXCHANGE -----------##
        if disable_ecdh:
            host_private_key, host_public_key_enc = generate_dh_key_pairs()
        else:
            print("USING ECDH")
            host_private_key, host_public_key_enc = generate_ecdh_key_pairs()
        data = await reader.read(4)
        size = None
        serialized_RSA_client_public_key = None
        abort = False
        if data == b"HELO":
            size = await reader.read(2)
            serialized_RSA_client_public_key = await reader.read(int.from_bytes(size, "big"))
            initial_message = b"HELO" + len(serialized_RSA_server_public_key).to_bytes(2, "big") + serialized_RSA_server_public_key
            writer.write(initial_message)
            await writer.drain()
        else:
            abort = True
        data = await reader.read(5)
        if data == b"DHINI" and not abort:
            writer.write(len(host_public_key_enc).to_bytes(2, "big") + host_public_key_enc)
            await writer.drain()
        else:
            abort = True
        data = await reader.read(4)
        if data == b"PUBK" and not abort:
            # The ECDH Key
            size = await reader.read(2)
            remote_public_key_enc = await reader.read(int.from_bytes(size, "big"))
            print("Size of remote's public key: ", int.from_bytes(size, "big"))
            print("Remote's public key:\n", remote_public_key_enc)
            # The message signature
            size = await reader.read(2)
            remote_signature = await reader.read(int.from_bytes(size, "big"))
            intended_message = serialized_RSA_server_public_key + serialized_RSA_client_public_key + host_public_key_enc + remote_public_key_enc
            verify(load_pem_public_key(serialized_RSA_client_public_key), remote_signature, intended_message)
            print("Message Verified")
            # The host_signature to prove the intended public key was received
            host_message = serialized_RSA_server_public_key + remote_public_key_enc
            with lock:
                host_signature = sign(RSA_server_private_key, host_message)
            writer.write(len(host_signature).to_bytes(2, "big") + host_signature + b"DHFIN")
            await writer.drain()
            remote_public_key = load_der_public_key(remote_public_key_enc, default_backend())
            if disable_ecdh:
                shared_key = host_private_key.exchange(remote_public_key)
            else:
                shared_key = host_private_key.exchange(ec.ECDH(), remote_public_key)
            derived_key = HKDF(algorithm=hashes.SHA256(),length=32,salt=None,info=b'handshake data',).derive(shared_key)
            print("Derived Key:\n", derived_key)
            derived_iv = HKDF(algorithm=hashes.SHA256(),length=16,salt=None,info=b'aes ofb iv',).derive(shared_key)
            print("Derived IV:\n", derived_iv)
            # client_derived_keys_ivs[s] = (derived_key, derived_iv)
            ## --------- DH Key EXCHANGE -----------##
        else:
            abort = True
        while stream and not abort:
            # img,frame = vid.read()
            data = await reader.read(1024)
            if data == b'READY':
                # print("got a READY")
                with lock:
                    # print("got LOCK")
                    serializedFrame = pickle.dumps(outputFrame)
                    # print("serializedFrame")
                    # print(serializedFrame[:10])
                    encr_serializedFrame = encrypt(derived_key, serializedFrame, derived_iv)
                    # print("encr_serializedFrame")
                    # print(encr_serializedFrame[:10])
                    message = struct.pack("Q",len(encr_serializedFrame))+encr_serializedFrame
                    # print(struct.pack("Q",len(encr_serializedFrame)))
                    # message = len(serializedFrame).to_bytes(8, "big")+serializedFrame
                    # print(len(serializedFrame).to_bytes(8, "big"))
                # print("sending FRAME")
                writer.write(message)
                await writer.drain()
            elif data == b'LEAVING':
                break    
            if outputFrame is not None:
                pass
                # # Show the image, debugging
                # cv2.imshow('SERVER STREAMING VIDEO',outputFrame)
                # # Way to close the feed, required for imshow to work properly
                # key = cv2.waitKey(1) & 0xFF
                # if key ==ord('q') or not stream:
                #     # client_socket.close()
                #     break
    except KeyboardInterrupt as e:
        print("\nClient Task was canceled")
        stream = False
        loop.stop()
        # raise e
    except asyncio.TimeoutError:
        print('Client Timed out')
    finally:
        writer.close()

async def boot_server(host_ip, port):
    server = await asyncio.start_server(new_client, port=port, host=host_ip)
    # async with server:
    await server.serve_forever()

if __name__ == '__main__':
    # Handle arguments
    ap = argparse.ArgumentParser()
    ap.add_argument("-i", "--host-ip", type=str, required=False,
        help="ip address to serve on", default='127.0.0.1')
    ap.add_argument("-p", "--port", type=int, required=False,
        help="port number to listen to", default=9898)
    ap.add_argument("--pki-host-ip", type=str, required=False,
        help="ip address of the PKI server to connect to", default='127.0.0.1')
    ap.add_argument("--pki-port", type=int, required=False,
        help="PKI port number to connect to", default=7777)
    ap.add_argument("--rsa-pub-key", type=str, required=False,
        help="Path to RSA PEM public key", default='env/keys/server/public-key.pem')
    ap.add_argument("--rsa-priv-key", type=str, required=False,
        help="Path to RSA PEM private key", default='env/keys/server/private-key.pem')
    ap.add_argument("--disable-ecdh", type=bool, required=False,
        help="Disable Elliptic Curve key generation for Diffie-Hellman Key Exchange", default=False)
    args = vars(ap.parse_args())

    disable_ecdh = args["disable_ecdh"]
    RSA_server_public_key = None
    RSA_server_private_key = None
    with open(args["rsa_pub_key"], "rb") as key_file:
        RSA_server_public_key = load_pem_public_key(
            key_file.read()
        )
    with open(args["rsa_priv_key"], "rb") as key_file:
        RSA_server_private_key = load_pem_private_key(
            key_file.read(),
            password=None,
        )

    # Serialize keys
    serialized_RSA_server_public_key = RSA_server_public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    # ## --------- PKI Register Pub Keys START-----------##
    # pki_client_socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    # pki_host_ip = args["pki_host_ip"]
    # pki_port = args["pki_port"]
    # pki_client_socket.connect((pki_host_ip,pki_port))
    # response = registerPublicKey(pki_client_socket, serialized_RSA_server_public_key, RSA_server_private_key)
    # print("response:", response)
    # pki_client_socket.close()
    # ## --------- PKI Register Pub Keys END  -----------##

    print("Setting up server...")
    # Socket Create
    # server_socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    # server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    host_ip = args["host_ip"]
    port = args["port"]
    socket_address = (host_ip,port)

    # Socket Bind
    # server_socket.bind(socket_address)

    # Socket Listen
    # server_socket.listen(5)
    # server_socket.setblocking(False)

    
    # event = threading.Event()
    # threading.Thread(target=key_capture_thread, args=(server_socket,), name='key_capture_thread', daemon=True).start()
    cap_frame_thread = threading.Thread(target=capture_frames, args=(), name='capture_frames', daemon=False)
    cap_frame_thread.start()
    threads = []
    
    print("LISTENING AT:",socket_address)
    loop = asyncio.get_event_loop()
    loop.create_task(boot_server(host_ip, port))
    try:
        loop.run_forever()
        # event.wait()
    except KeyboardInterrupt:
        print("\nServer is manually shutting down")
        stream = False
        cap_frame_thread.join()
        # event.set()
    finally:
        print("Shutting Down Server")
        # try:
        #     loop.stop()
        #     loop.run_until_complete(loop.shutdown_asyncgens())
        # try:
        #     # loop.stop()
        #     pending = asyncio.all_tasks()
        #     for task in penging:
        #         task.cancel()
        #         with suppress(asyncio.CancelledError):
        #             loop.run_until_complete(task)
        #     # loop.stop()
        #     # loop.run_until_complete(loop.shutdown_asyncgens())
        # try:
        #     loop.stop()
        #     pending = asyncio.all_tasks()
        #     loop.run_until_complete(asyncio.gather(*pending))
        try:
            loop.stop()
            pending = asyncio.all_tasks()
            for task in pending:
                task.cancel()
                with suppress(asyncio.CancelledError):
                    loop.run_until_complete(task)
            # loop.run_until_complete(asyncio.gather(*pending))
        except RuntimeError as e:
            if e.args[0] == 'no running event loop':
                pass
            else:
                raise e
