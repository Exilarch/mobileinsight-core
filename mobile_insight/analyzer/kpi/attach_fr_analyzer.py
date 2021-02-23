#!/usr/bin/python
# Filename: attach_fr_analyzer.py
"""
attach_fr_analyzer.py
A KPI analyzer to monitor and manage attach procedure failure rate

Author: Andrew Oeung

"""

__all__ = ["AttachFrAnalyzer"]

try:
    import xml.etree.cElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET
from .kpi_analyzer import KpiAnalyzer
import datetime

class AttachFrAnalyzer(KpiAnalyzer):
    """
    A KPI analyzer to monitor and manage RRC connection failure rate
    """

    def __init__(self):
        KpiAnalyzer.__init__(self)

        self.cell_id = None

        self.kpi_measurements = {"failure_number": {"TIMEOUT": 0, "CONCURRENT": 0, "DETACH": 0, "PROTOCOL_ERROR": 0, "EMM": 0}}

        for kpi in self.kpi_measurements["failure_number"]:
          self.register_kpi("Retainability", "ATTACH_" + kpi + "_FAILURE", self.__emm_sr_callback)

        self.attach_req_timestamp = None
        self.attach_accept_timestamp = None
        self.pending_attach = False
        self.accepting_attach = False
        self.timeouts = 0
        self.prev_log = None
        self.T3410 = 15 # default 15, 85s in WB-S1 mode
        self.T3450 = 6 # default 6, 18s in WB-S1 mode
        self.threshold = 60 # Messages must be within this time threshold for certain failures

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

    def __reset_parameters(self):
        """
        Reset maintained information when attach terminates
        """
        self.attach_req_timestamp = None
        self.attach_accept_timestamp = None
        self.pending_attach = False
        self.accepting_attach = False
        self.prev_log = None
        self.timeouts = 0

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
                            # Attach accept
                            if field.get("show") == "66" and self.pending_attach:
                                if self.attach_accept_timestamp:
                                    delta = (curr_timestamp - self.attach_accept_timestamp).total_seconds()
                                    if 0 <= delta <= self.threshold:
                                        self.timeouts += 1
                                    else:
                                        self.timeouts = 0
                                if self.timeouts == 5:
                                    self.kpi_measurements["failure_number"]["TIMEOUT"] += 1
                                    self.store_kpi("KPI_Retainability_ATTACH_TIMEOUT_FAILURE", str(self.kpi_measurements["failure_number"]["TIMEOUT"]), curr_timestamp)
                                    self.__reset_parameters()
                                self.accepting_attach = True
                                self.attach_accept_timestamp = curr_timestamp
                                self.prev_log = log_xml
                                self.pending_attach = False
                                self.attach_req_timestamp = None
                            # Attach reject
                            elif field.get("value") == "68":
                                for child_field in log_xml.iter("field"):
                                    if child_field.get("name") == "nas_eps.emm.cause":
                                        cause_idx = str(child_field.get("show"))
                                        protocol_errors = ["96", "99", "100", "111"]
                                        normal_failures = ["3", "6", "7", "8", "11", "12", "13", "14", "15", "25", "35", "42"]
                                        if cause_idx in protocol_errors:
                                            self.kpi_measurements["failure_number"]["PROTOCOL_ERROR"] += 1
                                            self.store_kpi("KPI_Retainability_ATTACH_PROTOCOL_ERROR_FAILURE", str(self.kpi_measurements["failure_number"]["PROTOCOL_ERROR"]), curr_timestamp)
                                        elif cause_idx == "22":
                                            for subfield in log_xml.iter("field"):
                                                if subfield.get("showname") and "T3346" in subfield.get("showname"):
                                                    self.kpi_measurements["failure_number"]["EMM"] += 1
                                                    self.store_kpi("KPI_Retainability_ATTACH_EMM_FAILURE", str(self.kpi_measurements["failure_number"]["EMM"]), curr_timestamp)
                                        else:
                                            self.kpi_measurements["failure_number"]["EMM"] += 1
                                            self.store_kpi("KPI_Retainability_ATTACH_EMM_FAILURE", str(self.kpi_measurements["failure_number"]["EMM"]), curr_timestamp)
                                        self.log_warning("EMM cause: " + cause_idx)
                                self.__reset_parameters()
                            # Detach request (Network-initiated)
                            elif field.get("value") == "69":
                                if self.pending_attach and self.attach_req_timestamp:
                                    delta = (curr_timestamp - self.attach_req_timestamp).total_seconds()
                                    if 0 <= delta <= self.threshold:
                                        detach_type = ""
                                        cause_idx = -1
                                        for subfield in log_xml.iter("field"):
                                            if subfield.get("showname") and "Re-attach" in subfield.get("showname"):
                                                detach_type = subfield.get("showname")
                                            elif subfield.get("name") == "nas_eps.emm.cause":
                                                cause_idx = str(child_field.get("show"))
                                        # failure case if detach under these conditions
                                        if ("Re-attach not required" in detach_type and cause_idx != "2") or ("Re-attach required" in detach_type):
                                            self.kpi_measurements["failure_number"]["DETACH"] += 1
                                            self.store_kpi("KPI_Retainability_ATTACH_DETACH_FAILURE", str(self.kpi_measurements["failure_number"]["DETACH"]), curr_timestamp)
                                            self.__reset_parameters()

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
                            if self.pending_attach or self.accepting_attach:
                                delta = 0
                                if self.pending_attach:
                                    delta = (curr_timestamp - self.attach_req_timestamp).total_seconds()
                                else:
                                    delta = (curr_timestamp - self.attach_accept_timestamp).total_seconds()
                                if 0 <= delta <= self.threshold:
                                    prev_IE = {}
                                    curr_IE = {}
                                    # compile and compare mandatory information elements
                                    for prev_field in self.prev_log.iter("field"):
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
                                        self.store_kpi("KPI_Retainability_ATTACH_CONCURRENT_FAILURE", str(self.kpi_measurements["failure_number"]["CONCURRENT"]), curr_timestamp)
                                        self.__reset_parameters()
                            if self.attach_req_timestamp:
                                delta = (curr_timestamp - self.attach_req_timestamp).total_seconds()
                                if 0 <= delta <= self.threshold:
                                    self.timeouts += 1
                                else:
                                    self.timeouts = 0
                            if self.timeouts == 5:
                                self.kpi_measurements["failure_number"]["TIMEOUT"] += 1
                                self.store_kpi("KPI_Retainability_ATTACH_TIMEOUT_FAILURE", str(self.kpi_measurements["failure_number"]["TIMEOUT"]), curr_timestamp)
                                self.__reset_parameters()
                            self.pending_attach = True
                            self.attach_req_timestamp = curr_timestamp
                            self.prev_log = log_xml
                        # Attach complete
                        elif field.get("show") == "67":
                            if self.attach_accept_timestamp:
                                delta = (curr_timestamp - self.attach_accept_timestamp).total_seconds()
                                if 0 <= delta <= self.threshold:
                                    self.__reset_parameters()
                        # Detach request
                        elif field.get("show") == "69":
                            if self.pending_attach or self.accepting_attach:
                                delta = 0
                                if self.pending_attach:
                                    delta = (curr_timestamp - self.attach_req_timestamp).total_seconds()
                                else:
                                    delta = (curr_timestamp - self.attach_accept_timestamp).total_seconds()
                                if 0 <= delta <= self.threshold:
                                    self.kpi_measurements["failure_number"]["DETACH"] += 1
                                    self.store_kpi("KPI_Retainability_ATTACH_DETACH_FAILURE", str(self.kpi_measurements["failure_number"]["DETACH"]), curr_timestamp)
                                    self.__reset_parameters()
