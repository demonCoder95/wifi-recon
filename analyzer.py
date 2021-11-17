import os
import ouilookup
import capture
from frameprocessor import FrameProcessor
from featureparse import FeatureParser
import pyfiglet
from dbhandler import DBHandler

# Print the welcome text - for fun!
figlet_handler = pyfiglet.Figlet()
print(figlet_handler.renderText("Welcome to Wifi-Snooper!"))

capture_file = "capture-dir/pcapture"

# Use the frame capturing module
print("Capturing frames...")
frame_sniffer = capture.FrameCapture(duration=10, filename=capture_file)
frame_sniffer.start_capture("wlan1mon")
print("Frame capture successful! Performing feature extraction...")

# Use the frame processor to extract features into a file
frame_processor = FrameProcessor(capture_file)
frame_processor.process_capture_file()
print("All done!")

# Create a db handler for the feature parser to store data
db_handler = DBHandler()

feature_parser = FeatureParser(db_handler)
feature_parser.parse_beacon_data()
# feature_parser.parse_probe_data()

print("BYE!")