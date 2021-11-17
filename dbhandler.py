# This module handles the database operations of the
# application to store ap-related data.
import sqlite3

# TODO: add vendor ID information in the database schema

class DBHandler:
	table_name = "ap_data"
	table_schema = "(bssid TEXT NOT NULL, ssid TEXT, sup_rates TEXT, ext_sup_rates TEXT, sig_str TEXT, txmtr_type TEXT, group_cipher TEXT, pair_cipher TEXT, auth_type TEXT, PRIMARY KEY(bssid))"
	"""
	The Database schema is explained:
	bssid: the MAC address of the AP. This is the primary key and is constrained to be unique
	ssid: the SSID of the wifi AP, can be null, if the AP has disabled SSID broadcast
	sup_rates: Supported Rates (in Mbps) as broadcasted in beacons
	ext_sup_rates: Extended Supported Rates (in Mbps) as broadcasted in beacons
	sig_str: Signal strength (in dBm) from the AP
	txmtr_type: Type of broadcaster (for beacon frames), can be STA - station or AP- access point
	group_cipher: the Group Cipher Key (GCK) for broadcast encryption supported by the broadcaster
	pair_cipher: the Pairwise Cipher Key(PCK) for 1-1 encryption supported by the broadcaster
	auth_type: Authentication Type supported by the broadcaster
	"""
	def __init__(self):
		print("Initializing AP-Database...")
		self.con = sqlite3.connect("ap-database.db")
		self.cur = self.con.cursor()
		if not self.check_table_exists():
			# create the table if it doesn't exist
			query = "CREATE TABLE {} {}".format(DBHandler.table_name, DBHandler.table_schema)
			self.cur.execute(query)
		print("AP-Database initialized!")

	def check_table_exists(self):
		# the sqlite_master table holds a list of all tables
		self.cur.execute("SELECT * FROM sqlite_master WHERE type='table'")
		tables = self.cur.fetchall()
		for each_table in tables:
			if DBHandler.table_name in each_table:
				return True
		return False
			
	def __del__(self):
		print("Closing the database...")
		self.con.close()

	def store_ap_data(self, ap_data):
		# using an APData class object, generate a query for the DB
		values = ap_data.generate_query_text()
		# check for uniqueness violation, to ensure only new APs are saved
		try:	
			self.cur.execute("INSERT INTO " + DBHandler.table_name + " VALUES " + values)
			self.con.commit()
			print("Database updated with a new AP: {}".format(ap_data.bssid))
		except sqlite3.IntegrityError as e:
			# e.args provides arguments of the raised exception
			# most exceptions only have a single argument, the 
			# error message accessible from 0, same thing that
			# is used in the __str__ method of the exception.
			if "UNIQUE constraint failed" in e.__str__():
				print("Entry for {} already exists.".format(ap_data.bssid))

	def check_entry_exists(self, bssid):
		self.cur.execute("SELECT bssid FROM" + DBHandler.table_name + " where bssid='{}'".format(bssid))
		if len(self.cur.fetchone()) > 1:
			print("BSSID {} exists in the DB".format(bssid))
			return True
		else:
			return False