# This module will process the frame statistics gathered from tshark
# and parse them into more presentable format for reporting
import os

class FrameProcessor:
	beacon_file = "beacon-data"
	probe_response_file = "probe-response-data"
	def __init__(self, filename="capture-dir/pcapture"):
		self.filename = filename

	def process_capture_file(self):
		self._parse_probe_responses()
		self._parse_beacons()

	# parse probe response frames out of the pcap and extract the required fields
	def _parse_probe_responses(self):
		tshark_command = "sudo tshark -r " + self.filename + " -Tfields -e wlan.sa -e wlan.ssid -e wlan.da -Y wlan.fc.type_subtype==0x0005"
		os.system(tshark_command + " > tshark-out 2>/dev/null")
		os.system("sort tshark-out | uniq -w 17 >" + FrameProcessor.probe_response_file)

	# parse beacon frames out of the pcap and extract required fields
	def _parse_beacons(self):
		tshark_command = "sudo tshark -r " + self.filename + " -Tfields -e wlan.sa -e wlan.ssid -e wlan.supported_rates -e wlan.extended_supported_rates -e radiotap.dbm_antsignal -e wlan.fixed.capabilities.ess -e wlan.rsn.gcs.type -e wlan.rsn.pcs.type -e wlan.rsn.akms.type -Y wlan.fc.type_subtype==0x0008"
		os.system(tshark_command + " > tshark-out 2>/dev/null")
		os.system("sort tshark-out | uniq -w 17 > " + FrameProcessor.beacon_file)
		# cleanup
		os.system("rm tshark-out")