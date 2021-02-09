#!/usr/bin/python
# Filename: auth_fr_analyzer.py
"""
auth_fr_analyzer.py
A KPI analyzer to monitor failure types of authentication procedures

Author: Andrew Oeung
"""

__all__ = ["AuthFrAnalyzer"]

try:
		import xml.etree.cElementTree as ET
except ImportError:
		import xml.etree.ElementTree as ET
from .kpi_analyzer import KpiAnalyzer
import datetime

# full list refer to Table 9.9.3.9.1 in TS 24.301
EMM_cause = {'3': 'ILL_UE',
						 '6': 'ILL_ME',
						 '7': 'EPS_NOT_ALLOWED',
						 '8': 'EPS_NONEPS_NOT_ALLOWED',
						 '9': 'UE_ID_NOT_DERIVED',
						 '10': 'IMPLIC_DETACHED',
						 '11': 'PLMN_NOT_ALLOWED',
						 '12': 'TA_NOT_ALLOWED',
						 '13': 'ROAM_NOT_ALLOWED',
						 '14': 'EPS_NOT_ALLOWED_PLMN',
						 '15': 'NO_SUIT_CELL',
						 '18': 'CS_DOMAIN_NOT_AVAIL',
						 '19': 'ESM_FAILURE',
						 '20': 'MAC_FAILURE',
						 '21': 'SYNC_FAILURE',
						 '22': 'CONGESTION',
						 '25': 'NOT_AUTH_CSG',
						 '26': 'NON_EPS_UNACCEPT',
						 '35': 'REQ_SERVICE_NOT_AUTH',
						 '39': 'CS_NOT_AVAIL',
						 '40': 'NO_EPS_ACTIVATED'}

class AuthFrAnalyzer(KpiAnalyzer):
		"""
		A KPI analyzer to monitor and manage mobile authentication failure rate
		"""

		def __init__(self):
				KpiAnalyzer.__init__(self)

				self.cell_id = None

				self.kpi_measurements = {'failure_number': {'TIMEOUT': 0, 'MAC': 0, 'SYNCH': 0, 'NON_EPS': 0, 'TRANSMISSION_TAU': 0, 'TRANSMISSION_SERVICE': 0}}

				for kpi in self.kpi_measurements["failure_number"]:
					self.register_kpi("Retainability", "AUTH_" + kpi + "_FAILURE", self.__emm_sr_callback)

				self.auth_timestamp = None
				self.prev_log = None
				self.timeouts = 0
				self.pending_auth = False
				self.pending_TAU = False
				self.pending_service = False
				self.T3460 = 6 # in WB-S1 mode, T3460 should be 24 seconds. Default value, 6s, is assumed.
				self.threshold = 30 # Messages must be within this time threshold for certain failures
		        # Maintain timestamps of unfinished procedures for a potential handover failure.
		        self.handover_timestamps = {}
		        for process in ["Identification", "Security", "GUTI", "Authentication", "Attach", "Detach", "TAU"]:
		        	self.handover_timestamps[process] = datetime.datetime.min

				# add callback function
				self.add_source_callback(self.__emm_sr_callback)

		def set_source(self,source):
				"""
				Set the trace source. Enable the LTE EMM messages.

				:param source: the trace source.
				:type source: trace collector
				"""
				KpiAnalyzer.set_source(self,source)
				# enable LTE EMM logs
				source.enable_log("LTE_NAS_EMM_OTA_Incoming_Packet")
				source.enable_log("LTE_NAS_EMM_OTA_Outgoing_Packet")

		def __clear_counters(self):
				for key, value in self.kpi_measurements.items():
						if type(value) == type(1):
								self.kpi_measurements[key] = 0
						else:
								for sub_key, sub_value in value.items():
										value[sub_key] = 0

		def __emm_sr_callback(self, msg):
				"""
				The value for field.get('show') indicates the type of procedure for the message.
				For more information, refer to http://niviuk.free.fr/lte_nas.php
				"""
				if msg.type_id == "LTE_NAS_EMM_OTA_Incoming_Packet":
					log_item = msg.data.decode()
					log_item_dict = dict(log_item)
					if "Msg" in log_item_dict:
						log_xml = ET.XML(log_item_dict["Msg"])
						for field in log_xml.iter('field'):
							if field.get("name") == "nas_eps.nas_msg_emm_type":
								# TAU reject
								if field.get('show') == '75':
									self.pending_TAU = False
								# Service reject
								if field.get('show') == '78':
									self.pending_service = False
								# Service accept
								elif field.get('show') == '79':
									self.pending_service = False
								# Authentication request, referring to 
								elif field.get('show') == "82":
										if self.pending_auth and self.pending_service:
											if self.auth_timestamp:
												delta = (log_item_dict['timestamp'] - self.auth_timestamp).total_seconds()
											if 0 <= delta <= self.threshold:
												self.kpi_measurements['failure_number']['TRANSMISSION_SERVICE'] += 1
												self.store_kpi("KPI_Retainability_AUTH_TRANSMISSION_SERVICE_FAILURE", str(self.kpi_measurements['failure_number']['TRANSMISSION_SERVICE']), log_item_dict['timestamp'])
												self.pending_auth = False
												self.pending_service = False
												self.pending_TAU = False
												self.prev_log = None
												self.timeouts = 0
										elif self.pending_auth and self.pending_TAU:
											if self.auth_timestamp:
												delta = (log_item_dict['timestamp'] - self.auth_timestamp).total_seconds()
											if 0 <= delta <= self.threshold:
												self.kpi_measurements['failure_number']['TRANSMISSION_TAU'] += 1
												self.store_kpi("KPI_Retainability_AUTH_TRANSMISSION_TAU_FAILURE", str(self.kpi_measurements['failure_number']['TRANSMISSION_TAU']), log_item_dict['timestamp'])
												self.pending_auth = False
												self.pending_service = False
												self.pending_TAU = False
												self.prev_log = None
												self.timeouts = 0
										elif self.pending_auth:
											if self.auth_timestamp:
												delta = (log_item_dict['timestamp'] - self.auth_timestamp).total_seconds()
											if 0 <= delta <= self.threshold:
												self.timeouts += 1
											else:
												self.timeouts = 0
										if self.timeouts == 5:
											self.kpi_measurements['failure_number']['TIMEOUT'] += 1
											self.store_kpi("KPI_Retainability_AUTH_TIMEOUT_FAILURE", str(self.kpi_measurements['failure_number']['TRANSMISSION_TAU']), log_item_dict['timestamp'])
											self.pending_auth = False
											self.pending_service = False
											self.pending_TAU = False
											self.prev_log = None
											self.timeouts = 0
										self.auth_timestamp = log_item_dict["timestamp"]
										self.pending_auth = True
										self.prev_log = log_xml
								# '84' indicates Auth reject
								elif field.get('show') == '84':
									self.pending_auth = False
									self.pending_TAU = False
									self.pending_service = False
									self.timeouts = 0
									self.auth_timestamp = None
				elif msg.type_id == "LTE_NAS_EMM_OTA_Outgoing_Packet":
					log_item = msg.data.decode()
					log_item_dict = dict(log_item)
					if 'Msg' in log_item_dict:
						log_xml = ET.XML(log_item_dict['Msg'])
						# ET.dump(log_xml)
						for field in log_xml.iter('field'):
							if field.get('name') == "nas_eps.nas_msg_emm_type":
								# TAU request
								if field.get('show') == '72' and not self.pending_auth:
									self.pending_TAU = True
								# TAU complete
								elif field.get('show') == '74':
									self.pending_TAU = False
								# Auth response
								elif field.get('show') == '83':
									self.pending_auth = False
									self.pending_TAU = False
									self.pending_service = False
									self.timeouts = 0
									self.auth_timestamp = None
									# '92' indicates Auth failure
								elif field.get('show') == '92':
									for child_field in log_xml.iter('field'):
											if child_field.get('name') == 'nas_eps.emm.cause':
													cause_idx = str(child_field.get('show'))
													if cause_idx == '20':
														self.kpi_measurements['failure_number']['MAC'] += 1
														self.store_kpi("KPI_Retainability_AUTH_MAC_FAILURE", str(self.kpi_measurements['failure_number']['MAC']), log_item_dict['timestamp'])
													elif cause_idx == '21':
														self.kpi_measurements['failure_number']['SYNCH'] += 1
														self.store_kpi("KPI_Retainability_AUTH_SYNCH_FAILURE", str(self.kpi_measurements['failure_number']['SYNCH']), log_item_dict['timestamp'])
													elif cause_idx == '26':
														self.kpi_measurements['failure_number']['NON_EPS'] += 1
														self.store_kpi("KPI_Retainability_AUTH_NON_EPS_FAILURE", str(self.kpi_measurements['failure_number']['NON_EPS']), log_item_dict['timestamp'])
													else:
															self.log_warning("Unknown EMM cause: " + cause_idx)
									self.pending_auth = False
									self.pending_TAU = False
									self.pending_service = False
									self.timeouts = 0
									self.auth_timestamp = None
								# service request
								elif field.get('show') == '255' and not self.pending_auth:
									self.pending_service = True

				return 0





