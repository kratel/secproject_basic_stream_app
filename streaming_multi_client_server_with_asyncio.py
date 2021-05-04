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
from PIL import UnidentifiedImageError, ImageFile
import os
# Needed for network communication
import pickle
import struct
# Needed to handle async calls
import asyncio
# For encryption
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import dh, padding, ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import PublicFormat, \
    Encoding, load_der_public_key, load_pem_public_key, load_pem_private_key
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
# Needed for logging
import logging
# Needed for exit handling
from contextlib import suppress

# Setting to handle partial frames
ImageFile.LOAD_TRUNCATED_IMAGES = True
# Globals for handling the frames
outputFrame = None
lock = threading.Lock()
# Global to handle streaming loops
stream = True
# Vars for Select
read_list = []
write_list = []
message_queues = {}
dh_keyexchanges = {}
client_derived_keys_ivs = {}
p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF  # noqa: E501
g = 2
serialized_RSA_server_public_key = None
RSA_server_private_key = None
disable_ecdh = False
loop = None
restricted = False
trusted_keys_whitelist = {}

# thread that listens for any input, used to terminate stream loop
# def key_capture_thread(server_socket):
#     global stream
#     input()
#     stream = False
#     print("starting exit process")


def capture_frames():
    global outputFrame, lock, stream, message_queues
    main_logger = logging.getLogger("main")
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

            time.sleep(0.1)
            # print("captured a screenshot")
            # print(stream)
    except UnidentifiedImageError as e:
        quoted_filename = e.args[0].split()[4]
        filename = quoted_filename.strip("'")
        if os.path.exists(filename):
            os.remove(filename)
            main_logger.info("Deleted leftover temp image file")
    except OSError as e:
        if e.errno == 2:
            main_logger.debug("During shutdown temp file was not written to disk, capture thread aborted")
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
    params_numbers = dh.DHParameterNumbers(p, g)
    parameters = params_numbers.parameters(default_backend())

    # Generate private and public key
    host_private_key = parameters.generate_private_key()
    host_public_key_enc = host_private_key.public_key().public_bytes(Encoding.DER,
                                                                     PublicFormat.SubjectPublicKeyInfo)
    return (host_private_key, host_public_key_enc)


def generate_ecdh_key_pairs():
    host_private_key = ec.generate_private_key(
        ec.SECP384R1()
    )
    host_public_key_enc = host_private_key.public_key().public_bytes(Encoding.DER,
                                                                     PublicFormat.SubjectPublicKeyInfo)
    return (host_private_key, host_public_key_enc)


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
    global lock, stream, outputFrame, serialized_RSA_server_public_key, RSA_server_private_key
    global disable_ecdh, loop, restricted, trusted_keys_whitelist
    main_logger = logging.getLogger("main")
    client_logger = logging.getLogger("client")
    addr = writer.get_extra_info('peername')
    main_logger.info(f"Client connected: {addr}")
    client_logger_extras = {'clientip': f"{addr[0]}", 'clientport': f"{addr[1]}"}
    client_logger = logging.LoggerAdapter(client_logger, client_logger_extras)
    try:
        # addr =  reader.get_extra_info('peername')
        # print(addr)
        # --------- DH Key EXCHANGE START -----------##
        if disable_ecdh:
            host_private_key, host_public_key_enc = generate_dh_key_pairs()
        else:
            host_private_key, host_public_key_enc = generate_ecdh_key_pairs()
        data = await reader.read(4)
        size = None
        serialized_RSA_client_public_key = None
        abort = False
        if data == b"HELO":
            size = await reader.read(2)
            serialized_RSA_client_public_key = await reader.read(int.from_bytes(size, "big"))
            initial_message = (b"HELO" +
                               len(serialized_RSA_server_public_key).to_bytes(2, "big") +
                               serialized_RSA_server_public_key)
            client_logger.debug(f"Public Key Received: {serialized_RSA_client_public_key}")
            if restricted:
                if serialized_RSA_client_public_key not in trusted_keys_whitelist:
                    client_logger.info("Rejecting client, not in whitelist")
                    initial_message = b"RJKT"
                    writer.write(initial_message)
                    await writer.drain()
                    abort = True
                    return
            writer.write(initial_message)
            await writer.drain()
        else:
            abort = True
            return
        data = await reader.read(5)
        if data == b"DHINI" and not abort:
            writer.write(len(host_public_key_enc).to_bytes(2, "big") + host_public_key_enc)
            await writer.drain()
        else:
            abort = True
            return
        data = await reader.read(4)
        if data == b"PUBK" and not abort:
            # The ECDH Key
            size = await reader.read(2)
            remote_public_key_enc = await reader.read(int.from_bytes(size, "big"))
            client_logger.debug(f"KeyExchange: Size of remote's public key: {int.from_bytes(size, 'big')}")
            client_logger.debug(f"Remote's public key: {remote_public_key_enc}")
            # The message signature
            size = await reader.read(2)
            remote_signature = await reader.read(int.from_bytes(size, "big"))
            intended_message = (serialized_RSA_server_public_key +
                                serialized_RSA_client_public_key +
                                host_public_key_enc +
                                remote_public_key_enc)
            verify(load_pem_public_key(serialized_RSA_client_public_key), remote_signature, intended_message)
            client_logger.info("Message Verified")
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
            # client_derived_keys_ivs[s] = (derived_key, derived_iv)
            # --------- DH Key EXCHANGE END -----------##

            derived_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'handshake data',).derive(shared_key)  # noqa: E501
            client_logger.debug(f"Derived Key: {derived_key}")
            derived_iv = HKDF(algorithm=hashes.SHA256(), length=16, salt=None, info=b'aes ofb iv',).derive(shared_key)  # noqa: E501
            client_logger.debug(f"Derived IV: {derived_iv}")

            # HMAC key
            derived_hmac_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'mac',).derive(shared_key)  # noqa: E501
            client_logger.debug(f"Derived HMAC Key: {derived_hmac_key}")
            # Session ID
            derived_session_id = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'session id',).derive(shared_key)  # noqa: E501
            client_logger.debug(f"Derived Session ID: {derived_session_id}")
            component_id = 1
        else:
            abort = True
            return
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
                message = derived_session_id
                bytes_component_id = component_id.to_bytes(4, "big")
                message += bytes_component_id
                # when width was 800
                # 1200165 when aspect ratio was 16:10
                # 1080165 when aspect ratio was 16:9
                # print("len encr_serializedFrame")
                # print(len(encr_serializedFrame))
                message += struct.pack("Q", len(encr_serializedFrame))+encr_serializedFrame
                # Make an hmac for message
                h = hmac.HMAC(derived_hmac_key, hashes.SHA256())
                h.update(message)
                message_hmac = h.finalize()
                message = message_hmac + message
                # print(struct.pack("Q",len(encr_serializedFrame)))
                # message = len(serializedFrame).to_bytes(8, "big")+serializedFrame
                # print(len(serializedFrame).to_bytes(8, "big"))
                # print("sending FRAME")
                writer.write(message)
                await writer.drain()
                component_id += 1
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
    except KeyboardInterrupt:
        client_logger.info("Client Task was canceled")
        stream = False
        loop.stop()
    except asyncio.TimeoutError:
        client_logger.info('Client Timed out')
    except ConnectionResetError:
        client_logger.info('Client left unexpectdly')
    finally:
        writer.close()
        client_logger.info('Connection Closed')


async def boot_server(host_ip, port):
    server = await asyncio.start_server(new_client, port=port, host=host_ip)
    # async with server:
    await server.serve_forever()


def str2bool(arg):
    if isinstance(arg, bool):
        return arg
    if arg.lower() in ('yes', 'true', 't', 'y', '1'):
        return True
    elif arg.lower() in ('no', 'false', 'f', 'n', '0'):
        return False
    else:
        raise argparse.ArgumentTypeError("Boolean value expected:\n\t'yes', 'true', 't', 'y', '1', 'no', 'false', 'f', 'n', '0'")  # noqa: E501


if __name__ == '__main__':
    # Setup Logging
    main_logger_Format = '{"Timestamp":"%(asctime)s", "Logger":"%(name)s", "Level":"%(levelname)s", "Message":"%(message)s"}'  # noqa: E501
    main_logger = logging.getLogger("main")
    main_logger_ch = logging.StreamHandler()
    main_formatter = logging.Formatter(main_logger_Format)
    main_logger.setLevel(logging.WARNING)
    main_logger_ch.setLevel(logging.WARNING)

    client_logger_Format = '{"Timestamp":"%(asctime)s", "Logger":"%(name)s", "Level":"%(levelname)s", "ClientIP":"%(clientip)s", "ClientPort":"%(clientport)s", "Message":"%(message)s"}'  # noqa: E501
    client_logger = logging.getLogger("client")
    client_logger_ch = logging.StreamHandler()
    client_formatter = logging.Formatter(client_logger_Format)
    client_logger.setLevel(logging.WARNING)
    client_logger_ch.setLevel(logging.WARNING)

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
    ap.add_argument("--disable-ecdh", type=str2bool, required=False,
                    help="Disable Elliptic Curve key generation for Diffie-Hellman Key Exchange", default=False)
    ap.add_argument("--restricted", type=str2bool, required=False,
                    help="Enable restricted mode, requires --whitelist argument", default=False)
    ap.add_argument("--whitelist", type=str, required=False,
                    help="Path to folder containing trusted public keys", default="env/keys/server/trusted_keys")
    ap.add_argument("-l", "--log-level", type=str, required=False,
                    help="Level of logging: info, debug, warning, error, default: warning", default='warning')
    args = vars(ap.parse_args())

    if (args["log_level"].lower() not in ["info", "warning", "debug", "error"]):
        argparse.error('Unexpected log level entered. Valid choices are: info, error, warning, debug')

    if args["log_level"].lower() == "info":
        main_logger.setLevel(logging.INFO)
        main_logger_ch.setLevel(logging.INFO)
        client_logger.setLevel(logging.INFO)
        client_logger_ch.setLevel(logging.INFO)
    elif args["log_level"].lower() == "warning":
        main_logger.setLevel(logging.WARNING)
        main_logger_ch.setLevel(logging.WARNING)
        client_logger.setLevel(logging.WARNING)
        client_logger_ch.setLevel(logging.WARNING)
    elif args["log_level"].lower() == "debug":
        main_logger.setLevel(logging.DEBUG)
        main_logger_ch.setLevel(logging.DEBUG)
        client_logger.setLevel(logging.DEBUG)
        client_logger_ch.setLevel(logging.DEBUG)
    elif args["log_level"].lower() == "error":
        main_logger.setLevel(logging.ERROR)
        main_logger_ch.setLevel(logging.ERROR)
        client_logger.setLevel(logging.ERROR)
        client_logger_ch.setLevel(logging.ERROR)

    main_logger_ch.setFormatter(main_formatter)
    main_logger.addHandler(main_logger_ch)
    client_logger_ch.setFormatter(client_formatter)
    client_logger.addHandler(client_logger_ch)

    if (args["restricted"] and args["whitelist"] == "env/keys/server/trusted_keys"):
        main_logger.warning('The --restricted argument is being run with the default whitelist')

    restricted = args["restricted"]
    if args["restricted"]:
        main_logger.info("Server is running in restricted mode, setting up whitelist...")
        # For every file in whitelist directory
        filenames = [f for f in os.listdir(args["whitelist"]) if os.path.isfile(os.path.join(args["whitelist"], f))]
        # Load the public key and add it to whitelist
        for pubkfile in filenames:
            RSA_trusted_client_public_key = None
            with open(os.path.join(args["whitelist"], pubkfile), "rb") as key_file:
                RSA_trusted_client_public_key = load_pem_public_key(
                    key_file.read()
                )
            serialized_RSA_trsuted_client_public_key = RSA_trusted_client_public_key.public_bytes(Encoding.PEM,
                                                                                                  PublicFormat.SubjectPublicKeyInfo)  # noqa: E501
            trusted_keys_whitelist[serialized_RSA_trsuted_client_public_key] = "Trusted"
        main_logger.info(f"{len(trusted_keys_whitelist)} Public Key(s) loaded into whitelist")
        main_logger.debug(f"trusted_keys_whitelist = {trusted_keys_whitelist}")

    disable_ecdh = args["disable_ecdh"]
    if disable_ecdh:
        main_logger.info("ECDH is disabled, using DSA keys with Diffie-Hellman")
    else:
        main_logger.info("Using ECDH for key exchange")
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
    serialized_RSA_server_public_key = RSA_server_public_key.public_bytes(Encoding.PEM,
                                                                          PublicFormat.SubjectPublicKeyInfo)
    # ## --------- PKI Register Pub Keys START-----------##
    # pki_client_socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    # pki_host_ip = args["pki_host_ip"]
    # pki_port = args["pki_port"]
    # pki_client_socket.connect((pki_host_ip,pki_port))
    # response = registerPublicKey(pki_client_socket, serialized_RSA_server_public_key, RSA_server_private_key)
    # print("response:", response)
    # pki_client_socket.close()
    # ## --------- PKI Register Pub Keys END  -----------##

    main_logger.info("Setting up server...")
    host_ip = args["host_ip"]
    port = args["port"]
    socket_address = (host_ip, port)
    cap_frame_thread = threading.Thread(target=capture_frames, args=(), name='capture_frames', daemon=False)
    cap_frame_thread.start()
    threads = []

    main_logger.info(f"LISTENING AT: {socket_address}")
    loop = asyncio.get_event_loop()
    loop.create_task(boot_server(host_ip, port))
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        main_logger.info("Server is manually shutting down")
        stream = False
        cap_frame_thread.join()
    finally:
        main_logger.info("Shutting Down Server")
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
                main_logger.debug("Lagging client task has been cancelled")
                with suppress(asyncio.CancelledError):
                    loop.run_until_complete(task)
            # loop.run_until_complete(asyncio.gather(*pending))
        except RuntimeError as e:
            if e.args[0] == 'no running event loop':
                main_logger.debug("All Client Connections have been closed already")
                pass
            else:
                raise e
