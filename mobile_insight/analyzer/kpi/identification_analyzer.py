#!/usr/bin/python
# Filename: identification_analyzer.py
"""
identification_analyzer.py
A KPI analyzer to monitor identification failures.

Author: Andrew Oeung
"""

__all__ = ["identification_analyzer"]

try:
    import xml.etree.cElementTree as ET 
except ImportError:
    import xml.etree.ElementTree as ET
from .kpi_analyzer import KpiAnalyzer 
import datetime


class IdentificationAnalyzer(KpiAnalyzer):
    """
    A KPI analyzer to monitor identification failures.
    """

    def __init__(self):
        KpiAnalyzer.__init__(self)

        self.cell_id = None
        self.kpi_measurements = {"failure_number": {"COLLISION": 0, "TRANSMISSION_TAU": 0, "TRANSMISSION_SERVICE": 0, "TIMEOUT": 0, "CONCURRENT": 0, "UNAVAILABLE": 0, "HANDOVER": 0}}

        for kpi in self.kpi_measurements["failure_number"]:
            self.register_kpi("Retainability", "IDENTIFY_" + kpi + "_FAILURE", self.__emm_sr_callback)

        self.identify_req_timestamp = None
        self.pending_id = False
        self.pending_attach = False
        self.pending_service = False
        self.pending_TAU = False
        self.timeouts = 0 # number of timeouts in a row for T3470
        self.prev_attach_log = None
        self.T3470 = 6 # in WB-S1 mode, T3470 should be 24. default value, 6, is assumed.
        self.threshold = 30 # Messages must be within this time threshold for certain failures

        # Maintain timestamps of unfinished procedures for a potential handover failure.
        self.handover_timestamps = {}
        for process in ["Identification", "Security", "GUTI", "Authentication", "Detach", "TAU"]:
            self.handover_timestamps[process] = datetime.datetime.min

        self.add_source_callback(self.__emm_sr_callback)

        self.prev_attach_log = None
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
        source.enable_log("LTE_RRC_OTA_Packet")

    def __clear_counters(self):
        for key, value in self.kpi_measurements.items():
            if type(value) == type(1):
                self.kpi_measurements[key] = 0
            else:
                for sub_key, sub_value in value.items():
                    value[sub_key] = 0

    def __reset_parameters(self):
        """
        Reset maintained information when identification terminates
        """
        self.timeouts = 0
        self.pending_id = False
        self.pending_attach = False
        self.pending_service = False
        self.pending_TAU = False
        self.prev_attach_log = False
        self.identify_req_timestamp = None
        self.handover_timestamps["Identification"] = datetime.datetime.min

    def __emm_sr_callback(self, msg):
        """
        The value for field.get("show") indicates the type of procedure for the message.
        For more information, refer to http://niviuk.free.fr/lte_nas.php
        """
        if msg.type_id == "LTE_NAS_EMM_OTA_Incoming_Packet":
            log_item = msg.data.decode()
            log_item_dict = dict(log_item)
            curr_timestamp = log_item_dict["timestamp"]
            if "Msg" in log_item_dict:
                log_xml = ET.XML(log_item_dict["Msg"])
                for field in log_xml.iter("field"):
                    if field.get("name") == "nas_eps.nas_msg_emm_type":
                        # "68" is attach reject
                        if field.get("show") == "68":
                            self.pending_attach = False
                        # "69" is detach request (network-initiated)
                        elif field.get("show") == "69":
                            self.handover_timestamps["Detach"] = curr_timestamp
                        # "70" is detach accept (UE-initiated)
                        elif field.get("show") == "70":
                            self.handover_timestamps["Detach"] = datetime.datetime.min
                        # "75" is TAU reject
                        elif field.get("show") == "75":
                            self.pending_TAU = False
                            self.handover_timestamps["TAU"] = datetime.datetime.min
                        # "78" is service reject, "79" is service accept
                        elif field.get("show") == "78" or field.get("show") == "79":
                            self.pending_service = False
                        # "80" is GUTI command
                        elif field.get("show") == "80":
                            self.handover_timestamps["GUTI"] = curr_timestamp
                        # "82" is authentication request
                        elif field.get("show") == "82":
                            self.handover_timestamps["Authentication"] = curr_timestamp
                        # "84" is authentication reject
                        elif field.get("show") == "84":
                            self.handover_timestamps["Authentication"] = datetime.datetime.min
                        # "85" is identification request
                        elif field.get("show") == "85":
                            # possible lower layer failure from service request -> identification
                            if self.pending_id and self.pending_service:
                                if self.identify_req_timestamp:
                                    delta = (curr_timestamp - self.identify_req_timestamp).total_seconds()
                                if 0 <= delta <= self.threshold:
                                    self.kpi_measurements["failure_number"]["TRANSMISSION_SERVICE"] += 1
                                    self.store_kpi("KPI_Retainability_IDENTIFY_TRANSMISSION_SERVICE_FAILURE", str(self.kpi_measurements["failure_number"]["TRANSMISSION_SERVICE"]), curr_timestamp)
                                    self.__reset_parameters()
                            # possible lower layer failure from TAU -> identification
                            elif self.pending_id and self.pending_TAU:
                                if self.identify_req_timestamp:
                                    delta = (curr_timestamp - self.identify_req_timestamp).total_seconds()
                                if 0 <= delta <= self.threshold:
                                    self.kpi_measurements["failure_number"]["TRANSMISSION_TAU"] += 1
                                    self.store_kpi("KPI_Retainability_IDENTIFY_TRANSMISSION_TAU_FAILURE", str(self.kpi_measurements["failure_number"]["TRANSMISSION_TAU"]), curr_timestamp)
                                    self.__reset_parameters()
                            # timeout failure
                            elif self.identify_req_timestamp and self.pending_id:
                                delta = (curr_timestamp - self.identify_req_timestamp).total_seconds()
                                if 0 <= delta <= self.threshold:
                                    self.timeouts += 1
                                else:
                                    self.timeouts = 0
                            if self.timeouts == 5:
                                self.kpi_measurements["failure_number"]["TIMEOUT"] += 1
                                self.store_kpi("KPI_Retainability_IDENTIFY_TIMEOUT_FAILURE", str(self.kpi_measurements["failure_number"]["TIMEOUT"]), curr_timestamp)
                                self.__reset_parameters()
                            self.pending_id = True
                            self.identify_req_timestamp = curr_timestamp
                            self.handover_timestamps["Identification"] = curr_timestamp
                        # "93" is Security mode command
                        elif field.get("show") == "93":
                            self.handover_timestamps["Security"] = curr_timestamp


        elif msg.type_id == "LTE_NAS_EMM_OTA_Outgoing_Packet":  
            log_item = msg.data.decode()
            log_item_dict = dict(log_item)
            curr_timestamp = log_item_dict["timestamp"]
            if "Msg" in log_item_dict:
                log_xml = ET.XML(log_item_dict["Msg"])
                for field in log_xml.iter("field"):
                    if field.get("name") == "nas_eps.nas_msg_emm_type":
                        # Attach request
                        if field.get("show") == "65":
                            if self.pending_id and not self.pending_attach:
                                delta = (curr_timestamp - self.identify_req_timestamp).total_seconds()
                                if 0 <= delta <= self.threshold:
                                    self.kpi_measurements["failure_number"]["COLLISION"] += 1
                                    self.store_kpi("KPI_Retainability_IDENTIFY_COLLISION_FAILURE", str(self.kpi_measurements["failure_number"]["COLLISION"]), curr_timestamp)
                                    self.__reset_parameters()
                            # failure case, different 2nd attach req with pending attach and pending ID
                            elif self.pending_id and self.pending_attach:
                                delta = (curr_timestamp - self.identify_req_timestamp).total_seconds()
                                if 0 <= delta <= self.threshold:
                                    prev_IE = {}
                                    curr_IE = {}
                                    # compile and compare mandatory information elements
                                    for prev_field in self.prev_attach_log.iter("field"):
                                        if prev_field.get("name") == "gsm_a.L3_protocol_discriminator":
                                            prev_IE[prev_field.get("name")] = prev_field.get("showname")
                                        elif prev_field.get("name") == "nas_eps.security_header_type":
                                            prev_IE[prev_field.get("name")] = prev_field.get("showname")
                                        elif prev_field.get("name") == "nas_eps.nas_msg_emm_type":
                                            prev_IE[prev_field.get("name")] = prev_field.get("showname")
                                        elif prev_field.get("name") == "nas_eps.emm.eps_att_type":
                                            prev_IE[prev_field.get("name")] = prev_field.get("showname")
                                        elif prev_field.get("name") == "nas_eps.emm.nas_key_set_id":
                                            prev_IE[prev_field.get("name")] = prev_field.get("showname")
                                        elif prev_field.get("name") == "nas_eps.emm.type_of_id":
                                            prev_IE[prev_field.get("name")] = prev_field.get("showname")
                                        elif prev_field.get("name") == "nas_eps.emm.esm_msg_cont":
                                            prev_IE[prev_field.get("name")] = prev_field.get("showname")
                                    for field in log_xml.iter("field"):
                                        if field.get("name") == "gsm_a.L3_protocol_discriminator":
                                            curr_IE[field.get("name")] = field.get("showname")
                                        elif field.get("name") == "nas_eps.security_header_type":
                                            curr_IE[field.get("name")] = field.get("showname")
                                        elif field.get("name") == "nas_eps.nas_msg_emm_type":
                                            curr_IE[field.get("name")] = field.get("showname")
                                        elif field.get("name") == "nas_eps.emm.eps_att_type":
                                            curr_IE[field.get("name")] = field.get("showname")
                                        elif field.get("name") == "nas_eps.emm.nas_key_set_id":
                                            curr_IE[field.get("name")] = field.get("showname")
                                        elif field.get("name") == "nas_eps.emm.type_of_id":
                                            curr_IE[field.get("name")] = field.get("showname")
                                        elif field.get("name") == "nas_eps.emm.esm_msg_cont":
                                            curr_IE[field.get("name")] = field.get("showname")
                                    if prev_IE != curr_IE:
                                        self.kpi_measurements["failure_number"]["CONCURRENT"] += 1
                                        self.store_kpi("KPI_Retainability_IDENTIFY_CONCURRENT_FAILURE", str(self.kpi_measurements["failure_number"]["CONCURRENT"]), curr_timestamp)
                                        self.__reset_parameters()
                            self.attach_req_timestamp = curr_timestamp
                            self.pending_attach = True
                            self.prev_attach_log = log_xml
                        # Attach complete
                        elif field.get("show") == "67":
                            self.pending_attach = False
                            self.prev_attach_log = None
                            self.attach_req_timestamp = None
                        # Detach request (UE-initiated)
                        elif field.get("show") == "69":
                            if self.pending_id:
                                delta = (curr_timestamp - self.identify_req_timestamp).total_seconds()
                                if 0 <= delta <= self.threshold:
                                    for subfield in log_xml.iter("field"):
                                        # failure case. detach with switch off field and pending ID.
                                        if subfield.get("showname") and "Switch off" in subfield.get("showname"):
                                            self.kpi_measurements["failure_number"]["COLLISION"] += 1
                                            self.store_kpi("KPI_Retainability_IDENTIFY_COLLISION_FAILURE", self.kpi_measurements["failure_number"]["COLLISION"], curr_timestamp)
                                            self.__reset_parameters()
                        # Detach accept (network-initiated)
                        elif field.get("show") == "70":
                            self.handover_timestamps["Detach"] = datetime.datetime.min
                        # TAU request
                        elif field.get("show") == "72":
                            if not self.pending_id:
                                self.pending_TAU = True
                            self.handover_timestamps["TAU"] = curr_timestamp
                        # TAU complete
                        elif field.get("show") == "74":
                            self.pending_TAU = False
                            self.handover_timestamps["TAU"] = datetime.datetime.min
                        # GUTI complete
                        elif field.get("show") == "81":
                            self.handover_timestamps["GUTI"] = datetime.datetime.min
                        # Auth response/failure
                        elif field.get("show") == "83" or field.get("show") == "92":
                            self.handover_timestamps["Authentication"] = datetime.datetime.min
                        # Identification response
                        elif field.get("show") == "86":
                            self.__reset_parameters()
                        # Security mode complete/reject
                        elif field.get("show") == "94" or field.get("show") == "95":
                            self.handover_timestamps["Security"] = datetime.datetime.min
                        # Service request
                        elif field.get("show") == "255" and not self.pending_id:
                            self.pending_service = True

                    # check for valid requested identity
                    elif field.get("name") == "gsm_a.ie.mobileid.type":
                        mobile_type = field.get("showname")
                        # failure case: requested identity unavailable. covers explicit no ID encoding as 
                        # well as exclusion of possible mobile type encodings.
                        if "no identity" in mobile_type:
                            self.kpi_measurements["failure_number"]["UNAVAILABLE"] += 1
                            self.store_kpi("KPI_Retainability_IDENTIFY_UNAVAILABLE_FAILURE", self.kpi_measurements["failure_number"]["UNAVAILABLE"], curr_timestamp)
                            self.__reset_parameters()          
                        elif "IMEISV" not in mobile_type and "TMSI/P-TMSI/M-TMSI" not in mobile_type and "IMSI" not in mobile_type:
                            self.kpi_measurements["failure_number"]["UNAVAILABLE"] += 1
                            self.store_kpi("KPI_Retainability_IDENTIFY_UNAVAILABLE_FAILURE", self.kpi_measurements["failure_number"]["UNAVAILABLE"], curr_timestamp)                  
                            self.__reset_parameters()
        elif msg.type_id == "LTE_RRC_OTA_Packet":
            log_item = msg.data.decode()
            log_item_dict = dict(log_item)
            curr_timestamp = log_item_dict["timestamp"]
            if "Msg" in log_item_dict:
                log_xml = ET.XML(log_item_dict["Msg"])
                for field in log_xml.iter("field"):
                    if field.get("name") == "lte-rrc.reestablishmentCause":
                        if "handoverFailure" in field.get("showname"):
                            last_id_timestamp = self.handover_timestamps["Identification"]
                            last_unfinished_timestamp = max(self.handover_timestamps.values())
                            if last_id_timestamp == last_unfinished_timestamp:
                                delta = (curr_timestamp - last_id_timestamp).total_seconds()
                                if 0 <= delta <= 600:
                                    self.kpi_measurements["failure_number"]["HANDOVER"] += 1
                                    self.store_kpi("KPI_Retainability_IDENTIFY_HANDOVER_FAILURE", self.kpi_measurements["failure_number"]["HANDOVER"], curr_timestamp)
                                    self.__reset_parameters()
