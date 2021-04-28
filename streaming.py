
import threading
import argparse
import datetime

import time

import numpy as np
import pyautogui
import imutils
import cv2



# The frame we end up sending
outputFrame = None
lock = threading.Lock()
stream = True

# thread that listens for any input, used to terminate stream loop
def key_capture_thread():
    global stream
    input()
    stream = False
    print("starting exit process")

def capture_frames():
	global outputFrame, lock
	threading.Thread(target=key_capture_thread, args=(), name='key_capture_thread', daemon=True).start()
	while stream:
		frame = pyautogui.screenshot()
		frame = cv2.cvtColor(np.array(frame), cv2.COLOR_RGB2BGR)
		# cv2.imwrite("in_memory_to_disk.png", image)

		# grab the current timestamp and draw it on the frame
		timestamp = datetime.datetime.now()
		cv2.putText(frame, timestamp.strftime(
			"%A %d %B %Y %I:%M:%S%p"), (10, frame.shape[0] - 10),
			cv2.FONT_HERSHEY_SIMPLEX, 0.35, (0, 0, 255), 1)

		with lock:
			outputFrame = frame.copy()
			cv2.imshow("RECEIVING VIDEO",outputFrame)

		time.sleep(0.5)
		print("captured a screenshot")

capture_frames()


