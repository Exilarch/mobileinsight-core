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
        self.kpi_measurements = {"failure_number": {"COLLISION": 0, "TRANSMISSION_TAU": 0, "TRANSMISSION_SERVICE": 0, "TIMEOUT": 0, "CONCURRENT": 0, "UNAVAILABLE": 0}}

        for kpi in self.kpi_measurements["failure_number"]:
            self.register_kpi("Retainability", "IDENTIFY_" + kpi + "_FAILURE", self.__emm_sr_callback)

        self.type = None
        self.identify_req_timestamp = None
        self.T3470 = 6 # in WB-S1 mode, T3470 should be 24. default value, 6, is assumed.
        self.pending_id = False
        self.pending_attach = False
        self.pending_service = False
        self.pending_TAU = False
        self.threshold = 30 # Messages must be within this time threshold for certain failures
        self.timeouts = 0 # number of timeouts in a row for T3470
        self.prev_attach_log = None
        # Maintain timestamps of unfinished procedures for a potential handover failure.
        self.handover_timestamps = {}

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
        # source.enable_log("LTE_RRC_OTA_Packet")

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
            # print(msg.type_id)
            log_item = msg.data.decode()
            log_item_dict = dict(log_item)
            if "Msg" in log_item_dict:
                log_xml = ET.XML(log_item_dict["Msg"])
                for field in log_xml.iter('field'):
                    if field.get("name") == "nas_eps.nas_msg_emm_type":
                        if field.get("show") == "68":
                            self.pending_attach = False
                        if field.get("show") == "75":
                            self.pending_TAU = False
                        if field.get("show") == "78":
                            self.pending_service = False
                        if field.get("show") == "79":
                            self.pending_service = False
                        # '85' indicates identification request
                        if field.get("show") == "85":
                            # possible lower layer failure from service request -> identification
                            if self.pending_id and self.pending_service:
                                if self.identify_req_timestamp:
                                    delta = (log_item_dict['timestamp'] - self.identify_req_timestamp).total_seconds()
                                if 0 <= delta <= self.threshold:
                                    self.kpi_measurements['failure_number']['TRANSMISSION_SERVICE'] += 1
                                    self.store_kpi("KPI_Retainability_IDENTIFY_TRANSMISSION_SERVICE_FAILURE", str(self.kpi_measurements['failure_number']['TRANSMISSION_SERVICE']), log_item_dict['timestamp'])
                                    self.timeouts = 0
                                    self.pending_id = False
                                    self.pending_attach = False
                                    self.pending_service = False
                                    self.pending_TAU = False
                                    self.prev_attach_log = False
                                    self.identify_req_timestamp = None
                            # possible lower layer failure from TAU -> identification
                            elif self.pending_id and self.pending_TAU:
                                if self.identify_req_timestamp:
                                    delta = (log_item_dict['timestamp'] - self.identify_req_timestamp).total_seconds()
                                if 0 <= delta <= self.threshold:
                                    self.kpi_measurements['failure_number']['TRANSMISSION_TAU'] += 1
                                    self.store_kpi("KPI_Retainability_IDENTIFY_TRANSMISSION_TAU_FAILURE", str(self.kpi_measurements['failure_number']['TRANSMISSION_TAU']), log_item_dict['timestamp'])
                                    self.timeouts = 0
                                    self.pending_id = False
                                    self.pending_attach = False
                                    self.pending_service = False
                                    self.pending_TAU = False
                                    self.prev_attach_log = False
                                    self.identify_req_timestamp = None
                            # timeout failure
                            elif self.identify_req_timestamp and self.pending_id:
                                delta = (log_item_dict["timestamp"] - self.identify_req_timestamp).total_seconds()
                                if 0 <= delta <= self.threshold:
                                    self.timeouts += 1
                                else:
                                    self.timeouts = 0
                            if self.timeouts == 5:
                                self.kpi_measurements['failure_number']['TIMEOUT'] += 1
                                self.store_kpi("KPI_Retainability_IDENTIFY_TIMEOUT_FAILURE", str(self.kpi_measurements['failure_number']['TIMEOUT']), log_item_dict['timestamp'])
                                self.timeouts = 0
                                self.pending_id = False
                                self.pending_attach = False
                                self.pending_service = False
                                self.pending_TAU = False
                                self.prev_attach_log = False
                                self.identify_req_timestamp = None
                            self.pending_id = True
                            self.identify_req_timestamp = log_item_dict["timestamp"]

        elif msg.type_id == "LTE_NAS_EMM_OTA_Outgoing_Packet":  
            log_item = msg.data.decode()
            log_item_dict = dict(log_item)
            if "Msg" in log_item_dict:
                log_xml = ET.XML(log_item_dict["Msg"])
                for field in log_xml.iter('field'):
                    if field.get("name") == "nas_eps.nas_msg_emm_type":
                        # attach request with code 65
                        if field.get('show') == '65':
                            # failure case. attach req with pending ID
                            if self.pending_id and not self.pending_attach:
                                self.kpi_measurements['failure_number']['COLLISION'] += 1
                                self.store_kpi("KPI_Retainability_IDENTIFY_COLLISION_FAILURE", str(self.kpi_measurements['failure_number']['COLLISION']), log_item_dict['timestamp'])
                                self.timeouts = 0
                                self.pending_id = False
                                self.pending_attach = False
                                self.pending_service = False
                                self.pending_TAU = False
                                self.prev_attach_log = False
                                self.identify_req_timestamp = None
                            
                            # failure case, diff 2nd attach req with pending attach and pending ID
                            elif self.pending_id and self.pending_attach:
                                # a dictionary of previous attach information elements
                                prev_IE = {}
                                curr_IE = {}
                                # compile information elements
                                for prev_field in self.prev_attach_log.iter("field"):
                                    if prev_field.get("name") == "nas_eps.emm.eps_att_type":
                                        prev_IE[prev_field.get("name")] = prev_field.get("showname")
                                    elif prev_field.get("name") == "nas_eps.emm.esm_msg_cont":
                                        prev_IE[prev_field.get("name")] = prev_field.get("showname")
                                    elif prev_field.get("name") == "nas_eps.emm.type_of_id":
                                        prev_IE[prev_field.get("name")] = prev_field.get("showname")
                                    elif prev_field.get("name") == "gsm_a.gm.gmm.ue_usage_setting":
                                        prev_IE[prev_field.get("name")] = prev_field.get("showname")
                                    elif prev_field.get("show") == "EPS mobile identity":
                                        prev_IE[prev_field.get("show")] = prev_field.get("showname")
                                    elif prev_field.get("show") == "UE network capability":
                                        prev_IE[prev_field.get("show")] = prev_field.get("showname")
                                    elif prev_field.get("show") == "DRX parameter":
                                        prev_IE[prev_field.get("show")] = prev_field.get("showname") 
                                for field in log_xml.iter("field"):
                                    if field.get("name") == "nas_eps.emm.eps_att_type":
                                        curr_IE[field.get("name")] = field.get("showname")
                                    elif field.get("name") == "nas_eps.emm.esm_msg_cont":
                                        curr_IE[field.get("name")] = field.get("showname")
                                    elif field.get("name") == "nas_eps.emm.type_of_id":
                                        curr_IE[field.get("name")] = field.get("showname")
                                    elif field.get("name") == "gsm_a.gm.gmm.ue_usage_setting":
                                        curr_IE[field.get("name")] = field.get("showname")
                                    elif field.get("show") == "EPS mobile identity":
                                        curr_IE[field.get("show")] = field.get("showname")
                                    elif field.get("show") == "UE network capability":
                                        curr_IE[field.get("show")] = field.get("showname")
                                    elif field.get("show") == "DRX parameter":
                                        curr_IE[field.get("show")] = field.get("showname")
                                if prev_IE != curr_IE:
                                    self.kpi_measurements['failure_number']['CONCURRENT'] += 1
                                    self.store_kpi("KPI_Retainability_IDENTIFY_CONCURRENT_FAILURE", str(self.kpi_measurements['failure_number']['CONCURRENT']), log_item_dict['timestamp'])
                                    self.timeouts = 0
                                    self.pending_id = False
                                    self.pending_attach = False
                                    self.pending_service = False
                                    self.pending_TAU = False
                                    self.prev_attach_log = False
                                    self.identify_req_timestamp = None
                            self.attach_req_timestamp = log_item_dict['timestamp']
                            self.pending_attach = True
                            self.prev_attach_log = log_xml

                        if field.get("show") == "67":
                            self.pending_attach = False
                            self.prev_attach_log = None
                            self.attach_req_timestamp = None
                        if field.get('show') == '69':
                            if self.pending_id:
                                # search for switch off
                                for subfield in log_xml.iter("field"):
                                    # failure case. detach with switch off field and pending ID.
                                    if subfield.get("showname") and "Switch off" in subfield.get("showname"):
                                        self.kpi_measurements["failure_number"]["COLLISION"] += 1
                                        self.store_kpi("KPI_Retainability_IDENTIFY_COLLISION_FAILURE", self.kpi_measurements["failure_number"]["COLLISION"], log_item_dict["timestamp"])
                                        self.timeouts = 0
                                        self.pending_id = False
                                        self.pending_attach = False
                                        self.pending_service = False
                                        self.pending_TAU = False
                                        self.prev_attach_log = False
                                        self.identify_req_timestamp = None
                        
                        if field.get("show") == "72" and not self.pending_id:
                            self.pending_TAU = True
                        if field.get("show") == "74":
                            self.pending_TAU = False
                        # '86' indicates identification response
                        if field.get("show") == "86":
                            self.timeouts = 0
                            self.pending_id = False
                            self.identify_req_timestamp = None
                        if field.get("show") == "255" and not self.pending_id:
                            self.pending_service = True

                    # check for valid requested identity
                    if field.get("name") == "gsm_a.ie.mobileid.type":
                        mobile_type = field.get("showname")
                        # failure case: requested identity unavailable. covers explicit no ID encoding as 
                        # well as exclusion of possible mobile type encodings.
                        if "no identity" in mobile_type:
                            self.kpi_measurements["failure_number"]["UNAVAILABLE"] += 1
                            self.store_kpi("KPI_Retainability_IDENTIFY_UNAVAILABLE_FAILURE", self.kpi_measurements["failure_number"]["UNAVAILABLE"], log_item_dict["timestamp"])
                                        
                        elif "IMEISV" not in mobile_type and "TMSI/P-TMSI/M-TMSI" not in mobile_type and "IMSI" not in mobile_type:
                            self.kpi_measurements["failure_number"]["UNAVAILABLE"] += 1
                            self.store_kpi("KPI_Retainability_IDENTIFY_UNAVAILABLE_FAILURE", self.kpi_measurements["failure_number"]["UNAVAILABLE"], log_item_dict["timestamp"])                  
        # use for RRC debugging.
        # elif msg.type_id == "LTE_RRC_OTA_Packet":
        #     # print(msg.type_id)
        #     log_item = msg.data.decode()
        #     log_item_dict = dict(log_item)
        #     if "Msg" in log_item_dict:
        #         log_xml = ET.XML(log_item_dict["Msg"])
        #         for field in log_xml.iter('field'):
        #             if field.get("showname"):
        #                 lfield = field.get("showname").lower()
        #                 if "failure" in lfield:
        #                     print(log_item)
        return 0