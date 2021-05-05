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
# Needed for network communication
import socket
import pickle
import struct
# Needed to handle non-blocking server socket
import select
import queue
# For encryption
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import PublicFormat, Encoding, load_der_public_key
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

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


# thread that listens for any input, used to terminate stream loop
def key_capture_thread(server_socket):
    global stream
    input()
    stream = False
    print("starting exit process")

def capture_frames():
    global outputFrame, lock, stream, message_queues
    # threading.Thread(target=key_capture_thread, args=(), name='key_capture_thread', daemon=True).start()
    while stream:
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

def server_dh_key_exchange(client_socket, host_private_key, host_public_key_enc):
    # Send size of public key and public key to remote
    client_socket.send(len(host_public_key_enc).to_bytes(2, "big") + host_public_key_enc)
    print("Sent host's public key to ", caddr, ":", cport)

    # Receiving size of remote's public key and remote's public key
    size = client_socket.recv(2)
    remote_public_key_enc = client_socket.recv(int.from_bytes(size, "big"))
    print("Size of remote's public key: ", int.from_bytes(size, "big"))
    print("Remote's public key:\n", remote_public_key_enc)

    # Decode remote's public key
    remote_public_key = load_der_public_key(remote_public_key_enc, default_backend())

    # Generate shared key
    shared_key = host_private_key.exchange(remote_public_key)
    return shared_key

def encrypt_and_send_AES_OFB_message(client_socket, plaintext, key, iv):
    ciphertext = encrypt(key, plaintext, iv)
    client_socket.send(len(ciphertext).to_bytes(2, "big") + ciphertext)

# def new_client(client_socket):
#     global lock, stream, outputFrame, read_list, write_list
#     if client_socket:
#         # vid = cv2.VideoCapture(0)
#         # global outputFrame, lock
#         try:
#             while stream:
#                 # img,frame = vid.read()
#                 readable, writable, errored = select.select(read_list, write_list, [], 20)
#                 for s in writable:
#                     if s is client_socket:
#                         with lock:
#                             serializedFrame = pickle.dumps(outputFrame)
#                             message = struct.pack("Q",len(serializedFrame))+serializedFrame
#                             s.sendall(message)
#                 # for s in readable:
#                 #     if s is client_socket:
#                 #         s.recv(1024)
                    
#                 if outputFrame is not None:
#                     pass
#                     # # Show the image, debugging
#                     # cv2.imshow('SERVER STREAMING VIDEO',outputFrame)
#                     # # Way to close the feed, required for imshow to work properly
#                     # key = cv2.waitKey(1) & 0xFF
#                     # if key ==ord('q') or not stream:
#                     #     # client_socket.close()
#                     #     break
#         finally:
#             client_socket.close()
#             write_list.remove(client_socket)
#             read_list.remove(client_socket)


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
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    host_ip = args["host_ip"]
    port = args["port"]
    socket_address = (host_ip,port)

    # Socket Bind
    server_socket.bind(socket_address)

    # Socket Listen
    server_socket.listen(5)
    server_socket.setblocking(False)
    print("LISTENING AT:",socket_address)

    threading.Thread(target=key_capture_thread, args=(server_socket,), name='key_capture_thread', daemon=True).start()
    threading.Thread(target=capture_frames, args=(), name='capture_frames', daemon=True).start()
    threads = []
    read_list = [server_socket]
    write_list = []
    try: 
        while stream:
            print("Getting ready to select")
            readable, writable, errored = select.select(read_list, write_list, read_list, 20)
            print(readable)
            print(writable)
            print(errored)
            for s in readable:
                if s is server_socket:
                    print("waiting for connection - before accept")
                    client_socket,(caddr, cport) = server_socket.accept()
                    if client_socket:
                        print("waiting for connection - after accept")
                        print('GOT CONNECTION FROM: %s:%s' % (caddr, cport))
                        client_socket.setblocking(False)
                        read_list.append(client_socket)
                        message_queues[client_socket] = queue.Queue()
                        dh_keyexchanges[client_socket] = generate_dh_key_pairs()
                        # with lock:
                        #     serializedFrame = pickle.dumps(outputFrame)
                        #     message = struct.pack("Q",len(serializedFrame))+serializedFrame
                        #     message_queues[s].put(message)
                        # write_list.append(client_socket)
                else:
                    if s in dh_keyexchanges:
                        print("in dh key exchange")
                        data = s.recv(4)
                        print(data)
                        if data == b'HELO':
                            # s.recv(1)
                            message_queues[s].put(len(dh_keyexchanges[s][1]).to_bytes(2, "big") + dh_keyexchanges[s][1])
                            if s not in write_list:
                                write_list.append(s)
                        elif data == b'PUBK':
                            print(readable)
                            print(writable)
                            print(errored)
                            # Receiving size of remote's public key and remote's public key
                            size = s.recv(2)
                            remote_public_key_enc = s.recv(int.from_bytes(size, "big"))
                            print("Size of remote's public key: ", int.from_bytes(size, "big"))
                            print("Remote's public key:\n", remote_public_key_enc)

                            # Decode remote's public key
                            remote_public_key = load_der_public_key(remote_public_key_enc, default_backend())

                            # Generate shared key
                            shared_key = dh_keyexchanges[s][0].exchange(remote_public_key)
                            derived_key = HKDF(algorithm=hashes.SHA256(),length=32,salt=None,info=b'handshake data',).derive(shared_key)
                            print("Derived Key:\n", derived_key)
                            derived_iv = HKDF(algorithm=hashes.SHA256(),length=16,salt=None,info=b'aes ofb iv',).derive(shared_key)
                            print("Derived IV:\n", derived_iv)
                            client_derived_keys_ivs[s] = (derived_key, derived_iv)
                            del dh_keyexchanges[s]
                            if s not in write_list:
                                write_list.append(s)
                    else:
                        print("reading from a non server socket")
                        data = s.recv(1024)
                        print("reading from a non server socket")
                        if data == b'READY':
                            with lock:
                                serializedFrame = pickle.dumps(outputFrame)
                                message = struct.pack("Q",len(serializedFrame))+serializedFrame
                                message_queues[s].put(message)
                            if s not in write_list:
                                write_list.append(s)
                        elif data == b'LEAVING':
                            if s in write_list:
                                write_list.remove(s)
                            read_list.remove(s)
                            s.close()
                            del message_queues[s]
                        else:
                            print("going to remove a non server socket")
                            if s in write_list:
                                write_list.remove(s)
                            read_list.remove(s)
                            s.close()
                            del message_queues[s]
                            # connThread = threading.Thread(target=new_client, args=(client_socket,))
                            # threads.append(connThread)
                            # read_list.append(client_socket)
                            # write_list.append(client_socket)
                            # connThread.start()
            for s in writable:
                print("in write_list")
                try:
                    print("in try in write_list")
                    next_msg = message_queues[s].get_nowait()
                except queue.Empty:
                    # if not s in dh_keyexchanges:
                    print("in except in write_list")
                    write_list.remove(s)
                else:
                    print("sending in write_list")
                    s.send(next_msg)

            for s in errored:
                print("in errored")
                read_list.remove(s)
                if s in writable:
                    write_list.remove(s)
                s.close()
                del message_queues[s]

            if not stream:
                # read_list.pop()
                break
            # if client_socket:
            #     # vid = cv2.VideoCapture(0)
            #     # global outputFrame, lock
            #     try:
            #         while stream:
            #             # img,frame = vid.read()
            #             with lock:
            #                 serializedFrame = pickle.dumps(outputFrame)
            #                 message = struct.pack("Q",len(serializedFrame))+serializedFrame
            #                 client_socket.sendall(message)
                            
            #             if outputFrame is not None:
            #                 pass
            #                 # # Show the image, debugging
            #                 # cv2.imshow('SERVER STREAMING VIDEO',outputFrame)
            #                 # # Way to close the feed, required for imshow to work properly
            #                 # key = cv2.waitKey(1) & 0xFF
            #                 # if key ==ord('q') or not stream:
            #                 #     # client_socket.close()
            #                 #     break
            #     finally:
            #         client_socket.close()
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
