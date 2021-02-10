#!/usr/bin/python
# Filename: security_mode_control_fr_analyzer.py
"""
security_mode_control_fr_analyzer.py
A KPI analyzer to monitor and manage security mode control failure rate

Author: Andrew Oeung

"""

__all__ = ["security_mode_control_fr_analyzer"]

try:
    import xml.etree.cElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET
from .kpi_analyzer import KpiAnalyzer
import datetime
class SecurityModeControlFrAnalyzer(KpiAnalyzer):
    """
    An KPI analyzer to monitor and manage security mode control failure rate
    """

    def __init__(self):
        KpiAnalyzer.__init__(self)

        self.cell_id = None

        self.kpi_measurements = {"failure_number": {"TRANSMISSION_TAU": 0, "TRANSMISSION_SERVICE": 0, "TIMEOUT": 0, "COLLISION": 0, "HANDOVER": 0}}

        for kpi in self.kpi_measurements["failure_number"]:
            self.register_kpi("Retainability", "SECURITY_" + kpi + "_FAILURE", self.__emm_sr_callback)

        self.security_mode_timestamp = None
        self.pending_security_mode = False
        self.pending_service = False
        self.pending_TAU = False
        self.timeouts = 0
        self.prev_log = None
        self.T3460 = 6 # in WB-S1 mode, T3460 should be 24 seconds. Default value, 6s, is assumed.
        self.threshold = 30 # keep an internal threshold between failure messages
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

        source.enable_log("LTE_NAS_EMM_OTA_Incoming_Packet")
        source.enable_log("LTE_NAS_EMM_OTA_Outgoing_Packet")
        source.enable_log("LTE_RRC_OTA_Packet")

    def __reset_parameters(self):
        """
        Reset maintained information when security mode terminates
        """
        self.timeouts = 0
        self.pending_security_mode = False
        self.pending_service = False
        self.pending_TAU = False
        self.prev_log = None
        self.security_mode_timestamp = None
        self.handover_timestamps["Security"] = datetime.datetime.min

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
                            # Detach request (network-initiated)
                            if field.get("show") == "69":
                                self.handover_timestamps["Detach"] = curr_timestamp
                            # Detach accept (UE-initiated)
                            elif field.get("show") == "70":
                                self.handover_timestamps["Detach"] = datetime.datetime.min
                            # TAU reject
                            elif field.get("show") == "75":
                                self.pending_TAU = False
                                self.handover_timestamps["TAU"] = datetime.datetime.min
                            # Service reject
                            elif field.get("show") == "78":
                                self.pending_service = False
                            # Service accept
                            elif field.get("show") == "79":
                                self.pending_service = False
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
                            # Security mode request
                            elif field.get("show") == "93":
                                if self.pending_security_mode and self.pending_service:
                                    if self.security_mode_timestamp:
                                        delta = (curr_timestamp - self.security_mode_timestamp).total_seconds()
                                    if 0 <= delta <= self.threshold:
                                        self.kpi_measurements["failure_number"]["TRANSMISSION_SERVICE"] += 1
                                        self.store_kpi("KPI_Retainability_SECURITY_TRANSMISSION_SERVICE_FAILURE", str(self.kpi_measurements["failure_number"]["TRANSMISSION_SERVICE"]), curr_timestamp)
                                        self.__reset_parameters()
                                elif self.pending_security_mode and self.pending_TAU:
                                    if self.security_mode_timestamp:
                                        delta = (curr_timestamp - self.security_mode_timestamp).total_seconds()
                                    if 0 <= delta <= self.threshold:
                                        self.kpi_measurements["failure_number"]["TRANSMISSION_TAU"] += 1
                                        self.store_kpi("KPI_Retainability_SECURITY_TRANSMISSION_TAU_FAILURE", str(self.kpi_measurements["failure_number"]["TRANSMISSION_TAU"]), curr_timestamp)
                                        self.__reset_parameters()
                                # check for retransmit
                                elif self.pending_security_mode:
                                    if self.security_mode_timestamp:
                                        delta = (curr_timestamp - self.security_mode_timestamp).total_seconds()
                                    if 0 <= delta <= self.threshold:
                                        self.timeouts += 1
                                    else:
                                        self.timeouts = 0
                                if self.timeouts == 5:
                                    self.kpi_measurements["failure_number"]["TIMEOUT"] += 1
                                    self.store_kpi("KPI_Retainability_SECURITY_TIMEOUT_FAILURE", str(self.kpi_measurements["failure_number"]["TIMEOUT"]), curr_timestamp)
                                    self.__reset_parameters()
                                self.security_mode_timestamp = curr_timestamp
                                self.pending_security_mode = True
                                self.prev_log = log_xml
                                self.handover_timestamps["Security"] = curr_timestamp
        elif msg.type_id == "LTE_NAS_EMM_OTA_Outgoing_Packet":
            log_item = msg.data.decode()
            log_item_dict = dict(log_item)
            curr_timestamp = log_item_dict["timestamp"]
            if "Msg" in log_item_dict:
                log_xml = ET.XML(log_item_dict["Msg"])
                for field in log_xml.iter("field"):
                    if field.get("name") == "nas_eps.nas_msg_emm_type":
                        # Attach/TAU/service request
                        if field.get("show") == "65" or field.get("show") == "72" or field.get("show") == "255":
                            if self.pending_security_mode:
                                if self.security_mode_timestamp:
                                    delta = (curr_timestamp - self.security_mode_timestamp).total_seconds()
                                    if 0 <= delta <= self.threshold:
                                        self.kpi_measurements["failure_number"]["COLLISION"] += 1
                                        self.store_kpi("KPI_Retainability_SECURITY_COLLISION_FAILURE", str(self.kpi_measurements["failure_number"]["COLLISION"]), curr_timestamp)
                                        self.__reset_parameters()
                            if field.get("show") == "72" and not self.pending_security_mode:
                                self.pending_TAU = True
                        # Detach request (UE-initiated)
                        elif field.get("show") == "69":
                            if self.pending_security_mode:
                                if self.security_mode_timestamp:
                                    delta = (curr_timestamp - self.security_mode_timestamp).total_seconds()
                                    if 0 <= delta <= self.threshold:
                                        for subfield in log_xml.iter("field"):
                                            if subfield.get("showname") and "Switch off" not in subfield.get("showname"):
                                                self.kpi_measurements["failure_number"]["COLLISION"] += 1
                                                self.store_kpi("KPI_Retainability_SECURITY_COLLISION_FAILURE", str(self.kpi_measurements["failure_number"]["COLLISION"]), curr_timestamp)
                                                self.__reset_parameters()
                            self.handover_timestamps["Detach"] = curr_timestamp
                        # Detach accept (Network-initiated)
                        elif field.get("show") == "70":
                            self.handover_timestamps["Detach"] = curr_timestamp
                        # TAU request
                        elif field.get("show") == "72":
                            if not self.pending_security_mode:
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
                            self.handover_timestamps["Identification"] = datetime.datetime.min
                        # Security mode complete/reject
                        elif field.get("show") == "94" or field.get("show") == "95":
                            self.__reset_parameters()
                        # Service request
                        elif field.get("show") == "255" and not self.pending_security_mode:
                            self.pending_service = True
        elif msg.type_id == "LTE_RRC_OTA_Packet":
            log_item = msg.data.decode()
            log_item_dict = dict(log_item)
            curr_timestamp = log_item_dict["timestamp"]
            if "Msg" in log_item_dict:
                log_xml = ET.XML(log_item_dict["Msg"])
                for field in log_xml.iter("field"):
                    if field.get("name") == "lte-rrc.reestablishmentCause":
                        if "handoverFailure" in field.get("showname"):
                            last_security_timestamp = self.handover_timestamps["Security"]
                            last_unfinished_timestamp = max(self.handover_timestamps.values())
                            if last_security_timestamp == last_unfinished_timestamp:
                                delta = (curr_timestamp - last_security_timestamp).total_seconds()
                                if 0 <= delta <= 600:
                                    self.kpi_measurements["failure_number"]["HANDOVER"] += 1
                                    self.store_kpi("KPI_Retainability_SECURITY_HANDOVER_FAILURE", self.kpi_measurements["failure_number"]["HANDOVER"], curr_timestamp)
                                    self.__reset_parameters()
