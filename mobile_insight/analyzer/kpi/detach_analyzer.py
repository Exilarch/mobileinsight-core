#!/usr/bin/python
# Filename: detach_analyzer.py
"""
detach_analyzer.py
A KPI analyzer to monitor and manage detach procedure success rate
Author: Andrew Oeung
"""

__all__ = ["DetachAnalyzer"]

try:
    import xml.etree.cElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET
from .kpi_analyzer import KpiAnalyzer
import datetime

class DetachAnalyzer(KpiAnalyzer):
    """
    A KPI analyzer to monitor and manage detach failure rate
    """

    def __init__(self):
        KpiAnalyzer.__init__(self)

        self.cell_id = None

        self.kpi_measurements = {"failure_number": {"TIMEOUT": 0, "COLLISION": 0, "EMM": 0, "HANDOVER": 0}}
        
        for kpi in self.kpi_measurements["failure_number"]:
          self.register_kpi("Retainability", "DETACH_" + kpi + "_FAILURE", self.__emm_sr_callback)

        self.detach_req_timestamp = None
        self.pending_detach = False
        self.timeouts = 0
        self.prev_log = None
        self.T3421 = 15 # default 15, 45s in WB-S1 mode
        self.T3422 = 6 # default 6, 24s in WB-S1 mode
        self.threshold = 60 # Messages must be within this time threshold for certain failures
        
        # Maintain timestamps of unfinished procedures for a potential handover failure.
        self.handover_timestamps = {}
        for process in ["Identification", "Security", "GUTI", "Authentication", "Detach", "TAU"]:
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
        Reset maintained information when detach terminates
        """
        self.timeouts = 0
        self.pending_detach = False
        self.prev_log = None
        self.detach_req_timestamp = None
        self.handover_timestamps["Detach"] = datetime.datetime.min

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
                        # Detach request (Network initiated)
                        if field.get("show") == "69":
                            for subfield in log_xml.iter("field"):
                                if subfield.get("name") == "nas_eps.emm.cause":
                                    cause_idx = str(subfield.get("show"))
                                    self.kpi_measurements["failure_number"]["EMM"] += 1
                                    self.store_kpi("KPI_Retainability_DETACH_EMM_FAILURE", str(self.kpi_measurements["failure_number"]["EMM"]), curr_timestamp)
                                    self.log_warning("EMM cause: " + cause_idx)
                                    self.__reset_parameters()
                            if self.detach_req_timestamp:
                                delta = (curr_timestamp - self.detach_req_timestamp).total_seconds()
                                if 0 <= delta <= self.threshold:
                                    self.timeouts += 1
                                else:
                                    self.timeouts = 0
                            if self.timeouts == 5:
                                self.kpi_measurements["failure_number"]["TIMEOUT"] += 1
                                self.store_kpi("KPI_Retainability_DETACH_TIMEOUT_FAILURE", str(self.kpi_measurements["failure_number"]["TIMEOUT"]), curr_timestamp)
                                self.__reset_parameters()
                            self.pending_detach = True
                            self.detach_req_timestamp = curr_timestamp
                            self.prev_log = log_xml
                            self.handover_timestamps["Detach"] = curr_timestamp
                        # Detach accept (UE initiated)
                        elif field.get("show") == "70":
                            self.__reset_parameters()
                        # TAU reject
                        elif field.get("show") == "75":
                            self.handover_timestamps["TAU"] = datetime.datetime.min
                        # GUTI command
                        elif field.get("show") == "80":
                            self.handover_timestamps["GUTI"] = curr_timestamp
                        # Auth request
                        elif field.get("show") == "82":
                            self.handover_timestamps["Authentication"] = curr_timestamp
                        # Auth reject
                        elif field.get("show") == "84":
                            self.handover_timestamps["Authentication"] = datetime.datetime.min
                        # Identification request
                        elif field.get("show") == "85":
                            self.handover_timestamps["Identification"] = curr_timestamp
                        # Security command
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
                            if self.pending_detach and self.detach_req_timestamp:
                                delta = (curr_timestamp - self.detach_req_timestamp).total_seconds()
                                if 0 <= delta <= self.threshold:
                                    for subfield in self.prev_log.iter("field"):
                                        detach_type = ""
                                        cause_idx = -1
                                        if subfield.get("showname"):
                                            if "re-attach" in subfield.get("showname").lower() or "imsi detach" in subfield.get("showname").lower():
                                                detach_type = subfield.get("showname").lower()
                                        elif subfield.get("name") == "nas_eps.emm.cause":
                                            cause_idx = str(subfield.get("show"))
                                    # failure case. detach with these conditions
                                    if ("re-attach not required" in detach_type and cause_idx != 2) or ("imsi detach" in detach_type and cause_idx != 2) or ("re-attach required" in detach_type):
                                        self.kpi_measurements["failure_number"]["COLLISION"] += 1
                                        self.store_kpi("KPI_Retainability_DETACH_COLLISION_FAILURE", str(self.kpi_measurements["failure_number"]["COLLISION"]), curr_timestamp)
                                        self.__reset_parameters()
                        # Detach request (UE initiated)
                        elif field.get("show") == "69":
                            if self.detach_req_timestamp:
                                delta = (curr_timestamp - self.detach_req_timestamp).total_seconds()
                                if 0 <= delta <= self.threshold:
                                    self.timeouts += 1
                                else:
                                    self.timeouts = 0
                            if self.timeouts == 5:
                                self.kpi_measurements["failure_number"]["TIMEOUT"] += 1
                                self.store_kpi("KPI_Retainability_DETACH_TIMEOUT_FAILURE", str(self.kpi_measurements["failure_number"]["TIMEOUT"]), curr_timestamp)
                                self.__reset_parameters()
                            self.pending_detach = True
                            self.detach_req_timestamp = curr_timestamp
                            self.prev_log = log_xml
                            self.handover_timestamps["Detach"] = curr_timestamp
                        # Detach accept (Network initiated)
                        elif field.get("show") == "70":
                            self.__reset_parameters()
                        # Tracking Area Update request
                        elif field.get("show") == "72":
                            if self.pending_detach and self.detach_req_timestamp:
                                delta = (curr_timestamp - self.detach_req_timestamp).total_seconds()
                                if 0 <= delta <= self.threshold:
                                    for subfield in self.prev_log.iter("field"):
                                        detach_type = ""
                                        cause_idx = -1
                                        if subfield.get("showname"):
                                            if "re-attach not required" in subfield.get("showname").lower() or "imsi detach" in subfield.get("showname").lower():
                                                detach_type = subfield.get("showname").lower()
                                        elif subfield.get("name") == "nas_eps.emm.cause":
                                            cause_idx = str(subfield.get("show"))
                                    # failure case. detach with these conditions
                                    if ("re-attach not required" in detach_type and cause_idx == 2) or ("imsi detach" in detach_type):
                                        self.kpi_measurements["failure_number"]["COLLISION"] += 1
                                        self.store_kpi("KPI_Retainability_DETACH_COLLISION_FAILURE", str(self.kpi_measurements["failure_number"]["COLLISION"]), curr_timestamp)
                                        self.__reset_parameters()
                            self.handover_timestamps["TAU"] = curr_timestamp
                        # TAU complete
                        elif field.get("show") == "74":
                            self.handover_timestamps["TAU"] = datetime.datetime.min
                        # GUTI complete
                        elif field.get("show") == "81":
                            self.handover_timestamps["GUTI"] = datetime.datetime.min
                        # Auth response/failure
                        elif field.get("show") == "83" or field.get("show") == "92":
                            self.handover_timestamps["Authentication"] = datetime.datetime.min
                        # Identification response
                        elif field.get("show") == "86":
                            self.handover_timestamps["Identification"] = datetime.datetime.min
                        # Security complete/reject
                        elif field.get("show") == "94" or field.get("show") == "95":
                            self.handover_timestamps["Security"] = datetime.datetime.min
        elif msg.type_id == "LTE_RRC_OTA_Packet":
            log_item = msg.data.decode()
            log_item_dict = dict(log_item)
            curr_timestamp = log_item_dict["timestamp"]
            if "Msg" in log_item_dict:
                log_xml = ET.XML(log_item_dict["Msg"])
                for field in log_xml.iter("field"):
                    if field.get("name") == "lte-rrc.reestablishmentCause":
                        if "handoverFailure" in field.get("showname"):
                            last_detach_timestamp = self.handover_timestamps["Detach"]
                            last_unfinished_timestamp = max(self.handover_timestamps.values())
                            if last_detach_timestamp == last_unfinished_timestamp:
                                delta = (curr_timestamp - last_detach_timestamp).total_seconds()
                                if 0 <= delta <= self.threshold:
                                    self.kpi_measurements["failure_number"]["HANDOVER"] += 1
                                    self.store_kpi("KPI_Retainability_DETACH_HANDOVER_FAILURE", self.kpi_measurements["failure_number"]["HANDOVER"], curr_timestamp)
                                    self.__reset_parameters()
