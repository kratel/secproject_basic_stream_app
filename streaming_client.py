import socket
import cv2
import pickle
import struct
import threading
import argparse
import errno

watching = True

# thread that listens for any input, used to terminate stream loop
def key_capture_thread():
    global watching
    input()
    watching = False
    print("starting exit process")


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
        # Initialize Connection
        client_socket.connect((host_ip,port)) # a tuple
        # initialize data var
        data = b""
        # Specify size as 8 bytes
        payload_size = struct.calcsize("Q")
        while watching:
            client_socket.sendall(b"READY")
            # Grab packet
            while len(data) < payload_size:
                packet = client_socket.recv(4*1024)
                print("some data received")
                if not packet: break
                data+=packet
            # Get packed size of received data, first 8 bytes of packet
            packed_msg_size = data[:payload_size]
            # Get the initial frame data, eveything after the first 8 bytes
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