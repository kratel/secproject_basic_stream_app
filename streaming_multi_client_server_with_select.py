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

# Globals for handling the frames
outputFrame = None
lock = threading.Lock()
stream = True
read_list = []
write_list = []
message_queues = {}


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
            for sq in message_queues:
                serializedFrame = pickle.dumps(outputFrame)
                message = struct.pack("Q",len(serializedFrame))+serializedFrame
                message_queues[sq].put(message)
            # cv2.imshow("RECEIVING VIDEO",outputFrame)
            # cv2.waitKey()

        # time.sleep(0.5)
        print("captured a screenshot")
        print(stream)

def new_client(client_socket):
    global lock, stream, outputFrame, read_list, write_list
    if client_socket:
        # vid = cv2.VideoCapture(0)
        # global outputFrame, lock
        try:
            while stream:
                # img,frame = vid.read()
                readable, writable, errored = select.select(read_list, write_list, [], 20)
                for s in writable:
                    if s is client_socket:
                        with lock:
                            serializedFrame = pickle.dumps(outputFrame)
                            message = struct.pack("Q",len(serializedFrame))+serializedFrame
                            s.sendall(message)
                # for s in readable:
                #     if s is client_socket:
                #         s.recv(1024)
                    
                if outputFrame is not None:
                    pass
                    # # Show the image, debugging
                    # cv2.imshow('SERVER STREAMING VIDEO',outputFrame)
                    # # Way to close the feed, required for imshow to work properly
                    # key = cv2.waitKey(1) & 0xFF
                    # if key ==ord('q') or not stream:
                    #     # client_socket.close()
                    #     break
        finally:
            client_socket.close()
            write_list.remove(client_socket)
            read_list.remove(client_socket)


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
                        # with lock:
                        #     serializedFrame = pickle.dumps(outputFrame)
                        #     message = struct.pack("Q",len(serializedFrame))+serializedFrame
                        #     message_queues[s].put(message)
                        write_list.append(client_socket)
                else:
                    print("reading from a non server socket")
                    data = s.recv(1024)
                    print("reading from a non server socket")
                    if data == b'READY':
                        # with lock:
                        #     serializedFrame = pickle.dumps(outputFrame)
                        #     message = struct.pack("Q",len(serializedFrame))+serializedFrame
                        #     message_queues[s].put(message)
                        if s not in write_list:
                            write_list.append(s)
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
                    print("in except in write_list")
                    # write_list.remove(s)
                else:
                    print("sending in write_list")
                    s.sendall(next_msg)

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
