# This script will take a list of MAC-address files as input,
# sanitize it (dedup) and perform OUI lookup online
# and output the vendor for each of the MAC addresses
# that have been found (uniquely) in the file
# Author: Noor
# Date: March 4, 2021

import requests
import time
import logging

logging.basicConfig(filename="oui-lookup.log", format="%(message)s", level=logging.INFO)

class OUILookup:
	def __init__(self, mac_list):
		self.mac_list = mac_list

	# update the mac_list for a lookup
	def set_mac_list(self, mac_list):
		self.mac_list = mac_list

	# perform the lookup for each mac_address
	def do_vendor_lookup(self):
		if len(self.mac_list) > 1:
			print("Looking up {} MAC addresses...".format(len(self.mac_list)))
		else:
			print("No MAC addresses found. Setup the MAC list and try again!")
			return

		# perform the lookup with the online database
		for mac_address in self.mac_list:
				
			# create the query string
			query = "http://api.macvendors.com/" + mac_address
			api_response = requests.get(query)

			if api_response.status_code == 200:
				response_text = "MAC: " + mac_address.strip() + "\t Vendor: " + api_response.text
			else:
				response_text = "MAC: " + mac_address.strip() + "\t Vendor: Unknown"
				
			logging.info(response_text)
			print(response_text)

			# limitation of the API
			time.sleep(1)
