# Given a tshark output file, parse the entities into reportable format
from frameprocessor import FrameProcessor
import ouilookup

class APData:
	def __init__(self, bssid, ssid, sup_rates, ext_sup_rates, sig_str, txmtr_type, group_cipher, pair_cipher, auth_type):
		self.bssid = bssid
		self.ssid = ssid
		self.sup_rates = sup_rates
		self.ext_sup_rates = ext_sup_rates
		self.sig_str = sig_str
		self.txmtr_type = txmtr_type
		self.group_cipher = group_cipher
		self.pair_cipher = pair_cipher
		self.auth_type = auth_type

	def generate_query_text(self):
		# using the data fields, can generate a query text for the DB
		# this will be a single string
		# reformat MAC address to re-w 17 >place : which is a special char
		return "('{}', '{}', '{}', '{}', '{}', '{}', '{}', '{}', '{}')".format(
			self.bssid,
			self.ssid,
			self.sup_rates,
			self.ext_sup_rates,
			self.sig_str,
			self.txmtr_type,
			self.group_cipher,
			self.pair_cipher,
			self.auth_type)

class FeatureParser:

	# The map which translates rates into mbps
	s_rate_mbps = {
		2:1,
		4:2,
		11:5.5,
		22:11,
		12:6,
		18:9,
		24:12,
		36:18,
		48:24,
		72:36,
		96:48,
		108:54
	}

	# Translate key ciphers into names
	cipher_suite = {
		2: "TKIP",
		4: "AES-CCMP"
	}

	# Translate auth types into names
	auth_type = {
		2: "PSK"
	}

	def __init__(self, db_handler, filename=FrameProcessor.beacon_file):
		self.filename = filename
		self.db_handler = db_handler

	def parse_beacon_data(self):
		self._parse_mac_and_lookup()
		print()
		# the main method that calls all other helpers
		with open(FrameProcessor.beacon_file, "r") as datafile:
			for each_line in datafile.readlines():
				# avoid parsing errors with fields
				each_line = each_line.strip()
				bssid = each_line.split('\t')[0]
				print("BSSID: {}".format(bssid))
				ssid = each_line.split('\t')[1]
				print("SSID: {}".format(ssid))
				mod_rates = self._parse_modulation_rates(each_line)
				sig_str = self._parse_signal_strength(each_line)
				txmtr_type = self._parse_transmitter_type(each_line)
				ciphers = self._parse_cipher_info(each_line)
				print()
				ap_data = APData(
					bssid, ssid, mod_rates[0], mod_rates[1],
					sig_str, txmtr_type, ciphers[0], ciphers[1], ciphers[2])
				# for debugging
				print(ap_data.generate_query_text())
				self.db_handler.store_ap_data(ap_data)

	def parse_probe_data(self):
		print("Associated STAs: ")
		with open(FrameProcessor.probe_response_file, "r") as datafile:
			for each_line in datafile.readlines():
				self._parse_probe_stations(each_line)

	def _parse_mac_and_lookup(self):
		# Extract MAC addresses
		print("Extracting MAC addresses..")
		mac_addresses = list()
		with open(FrameProcessor.beacon_file, "r") as datafile:
			for each_line in datafile.readlines():
				mac_addresses.append(each_line.split("\t")[0])
		print("Performing vendor lookup..")
		vendor_finder = ouilookup.OUILookup(mac_addresses)
		vendor_finder.do_vendor_lookup()

	# return an array with 2 elements, sup_rate/ex_sup_rate
	def _parse_modulation_rates(self, output_line):
		# APs can advertise their modulation rates as basic/extended rates
		# but the encoding remains the same, so can be handled with a single map
		supported_rates = output_line.split("\t")[2]
		supported_rates = supported_rates.split(",")
		# translate values into Mbit/s
		sr_mbits = [str(FeatureParser.s_rate_mbps[int(x)%128]) for x in supported_rates]
		sr_mbits = ",".join(sr_mbits)
		print("Supported base rates: {} Mbps".format(sr_mbits))

		ext_supported_rates = output_line.split("\t")[3]		
		ext_supported_rates = ext_supported_rates.split(",")
		print("Supported extended rates: ", end="")
		# Check support for extended rates, some APs might not have this
		if ext_supported_rates[0] != '':
			ext_supported_rates = [int(x)%128 for x in ext_supported_rates]
			# translate values into Mbit/s
			ex_sr_mbits = [str(FeatureParser.s_rate_mbps[int(x)%128]) for x in ext_supported_rates]
			ex_sr_mbits = ",".join(ex_sr_mbits)
			print(ex_sr_mbits, end=" ")
			print("Mbps")
		else:
			print("None")
			ex_sr_mbits = "none"

		return [sr_mbits, ex_sr_mbits]

	# parse only the antenna dBm gain
	def _parse_signal_strength(self, output_line):
		antenna_dbm = output_line.split('\t')[4].split(",")
		print("Signal strength: {}dBm".format(antenna_dbm[1]))
		return antenna_dbm[1]

	# determine if the transmitter is an AP
	def _parse_transmitter_type(self, output_line):
		ess_flag = int(output_line.split('\t')[5])
		if ess_flag == 0:
			print("Transmitter is a STA")
			return "STA"
		elif ess_flag == 1:
			print("Transmitter is an AP")
			return "AP"

	# parse the cipher information
	def _parse_cipher_info(self, output_line):
		if len(output_line.split('\t')) <=6:
			print("Open auth and no encryption!")
			return ["none", "none", "none"]

		group_cipher = output_line.split('\t')[6]
		if group_cipher == '':
			print("No group cipher supported!")
			group_cipher = "none"
		else:
			group_cipher = FeatureParser.cipher_suite[int(group_cipher)]
			print("Group Cipher: {}".format(group_cipher))

		pairwise_ciphers = output_line.split('\t')[7].split(",")
		if pairwise_ciphers[0] == '':
			print("No pairwise cipher supported!")
			pairwise_ciphers = "none"
		else:
			pairwise_ciphers = [FeatureParser.cipher_suite[int(x)] for x in pairwise_ciphers]
			pairwise_ciphers = ",".join(pairwise_ciphers)
			print("Pairwise Cipher(s): {}".format(pairwise_ciphers))

		auth_types = output_line.split('\t')[8].split(",")
		if auth_types[0] == '':
			print("No auth type supported!")
			auth_types = "none"
		else:
			auth_types = [FeatureParser.auth_type[int(x)] for x in auth_types]
			auth_types = ",".join(auth_types)
			print("Auth type(s): {}".format(auth_types))

		return [group_cipher, pairwise_ciphers, auth_types]

	# parse the potentially associated STAs
	def _parse_probe_stations(self, output_line):
		data = output_line.split('\t')
		print("AP MAC: {}\tAP SSID: {}\tProbing Client: {}\t".format(data[0], data[1], data[2]))