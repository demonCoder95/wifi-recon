# This module will perform a packet capture with tshark
# It will also perform the field extraction as configured
# by the fiters

import os

class FrameCapture:
	def __init__(self, duration=30, filename="capture-file"):
		self.duration = duration
		self.filename = filename
	
	# start capturing the packets on the monitoring interface
	def start_capture(self, interface):
		tshark_command = "sudo tshark -i " + interface + " -a duration:" + str(self.duration) + " -w " + self.filename + " 2>/dev/null"
		os.system(tshark_command)