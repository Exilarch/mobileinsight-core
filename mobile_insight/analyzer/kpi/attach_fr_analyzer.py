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
             '22': 'CONGESTION',
             '25': 'NOT_AUTH_CSG',
             '35': 'REQ_SERVICE_NOT_AUTH',
             '39': 'CS_NOT_AVAIL',
             '40': 'NO_EPS_ACTIVATED',
             '96': 'INVALID_MANDATORY_INFO',
             '99': 'IE_NOT_IMPLEMENTED',
             '100': 'CONDITIONAL_IE_ERROR',
             '111': 'PROTOCOL_ERROR'}

class AttachFrAnalyzer(KpiAnalyzer):
    """
    A KPI analyzer to monitor and manage RRC connection failure rate
    """

    def __init__(self):
        KpiAnalyzer.__init__(self)

        self.cell_id = None

        self.kpi_measurements = {'failure_number': {'TIMEOUT': 0, 'CONCURRENT': 0, 'DETACH': 0, 'PROTOCOL_ERROR': 0, 'EMM': 0}}

        for kpi in self.kpi_measurements["failure_number"]:
          self.register_kpi("Retainability", "ATTACH_" + kpi + "_FAILURE", self.__emm_sr_callback)

        self.attach_req_timestamp = None
        self.attach_accept_timestamp = None
        self.T3410 = 15 # default 15, 85s in WB-S1 mode
        self.T3450 = 6 # default 6, 18s in WB-S1 mode
        self.pending_attach = False
        self.accepting_attach = False
        self.prev_log = None
        self.timeouts = 0
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
                            # showing '66' indicates Attach accept, referring to http://niviuk.free.fr/lte_nas.php
                            if field.get('show') == '66' and self.pending_attach:
                                print("ATT accept")
                                if self.attach_accept_timestamp:
                                    delta = (log_item_dict['timestamp'] - self.attach_accept_timestamp).total_seconds()
                                    if 0 <= delta <= self.threshold:
                                        self.timeouts += 1
                                    else:
                                        self.timeouts = 0
                                if self.timeouts == 5:
                                    self.kpi_measurements['failure_number']['TIMEOUT'] += 1
                                    self.store_kpi("KPI_Retainability_ATTACH_TIMEOUT_FAILURE", str(self.kpi_measurements['failure_number']['TIMEOUT']), log_item_dict['timestamp'])
                                    self.accepting_attach = False
                                    self.prev_log = None
                                    self.timeouts = 0
                                    self.attach_accept_timestamp = None
                                self.accepting_attach = True
                                self.attach_accept_timestamp = log_item_dict['timestamp']
                                self.prev_log = log_xml
                                self.pending_attach = False
                                self.attach_req_timestamp = None
                            # '41' indicates Attach reject
                            elif field.get('value') == '68':
                                print("ATT reject")
                                for child_field in log_xml.iter('field'):
                                    if child_field.get('name') == 'nas_eps.emm.cause':
                                        cause_idx = str(child_field.get('show'))
                                        protocol_errors = ['96', '99', '100', '111']
                                        normal_failures = ['3', '6', '7', '8', '11', '12', '13', '14', '15', '25', '35', '42']
                                        if cause_idx in protocol_errors:
                                            self.kpi_measurements['failure_number']['PROTOCOL_ERROR'] += 1
                                            self.store_kpi('KPI_Retainability_ATTACH_PROTOCOL_ERROR_FAILURE', str(self.kpi_measurements['failure_number']['PROTOCOL_ERROR']), log_item_dict['timestamp'])
                                        elif cause_idx == '22':
                                            for subfield in log_xml.iter('field'):
                                                if subfield.get('showname') and 'T3346' in subfield.get('showname'):
                                                    self.kpi_measurements['failure_number']['EMM'] += 1
                                                    self.store_kpi('KPI_Retainability_ATTACH_EMM_FAILURE', str(self.kpi_measurements['failure_number']['EMM']), log_item_dict['timestamp'])
                                                    self.log_warning("EMM cause: " + cause_idx)
                                        else:
                                            self.kpi_measurements['failure_number']['EMM'] += 1
                                            self.store_kpi('KPI_Retainability_ATTACH_EMM_FAILURE', str(self.kpi_measurements['failure_number']['EMM']), log_item_dict['timestamp'])
                                            self.log_warning("EMM cause: " + cause_idx)
                                self.pending_attach = False
                                self.accepting_attach = False
                                self.attach_accept_timestamp = None
                                self.attach_req_timestamp = None
                                self.timeouts = 0
                                self.prev_log = None
                            elif field.get('value') == '69':
                                # Detach request to UE
                                if self.pending_attach and self.attach_req_timestamp:
                                    for subfield in log_xml.iter("field"):
                                        detach_type = ""
                                        cause_idx = -1
                                        if subfield.get("showname") and "re-attach" in subfield.get("showname").lower():
                                            detach_type = subfield.get("showname").lower()
                                        elif subfield.get('name') == 'nas_eps.emm.cause':
                                            cause_idx = str(child_field.get('show'))
                                    # failure case. detach with these conditions
                                    if ("re-attach not required" in detach_type and cause_idx != 2) or ("re-attach required" in detach_type):
                                        self.kpi_measurements['failure_number']['DETACH'] += 1
                                        self.store_kpi("KPI_Retainability_ATTACH_DETACH_FAILURE", str(self.kpi_measurements['failure_number']['CONCURRENT']), log_item_dict['timestamp'])
                                        self.timeouts = 0
                                        self.pending_attach = False
                                        self.accepting_attach = False
                                        self.prev_log = None
                                        self.attach_req_timestamp = None
                                        self.attach_accept_timestamp = None

        elif msg.type_id == "LTE_NAS_EMM_OTA_Outgoing_Packet":
            log_item = msg.data.decode()
            log_item_dict = dict(log_item)
            if 'Msg' in log_item_dict:
                log_xml = ET.XML(log_item_dict['Msg'])
                for field in log_xml.iter('field'):
                    if field.get('name') == "nas_eps.nas_msg_emm_type":
                        if field.get('show') == '65':
                            # Attach request, referring to http://niviuk.free.fr/lte_nas.php
                            print("ATT REQ")
                            if self.pending_attach or self.accepting_attach:
                                delta = 0
                                if self.pending_attach:
                                    delta = (log_item_dict['timestamp'] - self.attach_req_timestamp).total_seconds()
                                else:
                                    delta = (log_item_dict['timestamp'] - self.attach_accept_timestamp).total_seconds()
                                if 0 <= delta <= self.threshold:
                                    prev_IE = {}
                                    curr_IE = {}
                                    # compile information elements
                                    for prev_field in self.prev_log.iter("field"):
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
                                        self.store_kpi("KPI_Retainability_ATTACH_CONCURRENT_FAILURE", str(self.kpi_measurements['failure_number']['CONCURRENT']), log_item_dict['timestamp'])
                                        self.timeouts = 0
                                        self.pending_attach = False
                                        self.accepting_attach = False
                                        self.prev_log = None
                                        self.attach_accept_timestamp = None
                                        self.attach_req_timestamp = None
                            if self.attach_req_timestamp:
                                delta = (log_item_dict['timestamp'] - self.attach_req_timestamp).total_seconds()
                                if 0 <= delta <= self.threshold:
                                    self.timeouts += 1
                                else:
                                    self.timeouts = 0
                            if self.timeouts == 5:
                                self.kpi_measurements['failure_number']['TIMEOUT'] += 1
                                self.store_kpi("KPI_Retainability_ATTACH_TIMEOUT_FAILURE", str(self.kpi_measurements['failure_number']['TIMEOUT']), log_item_dict['timestamp'])
                                self.timeouts = 0
                                self.pending_attach = False
                                self.accepting_attach = False
                                self.prev_log = None
                                self.attach_accept_timestamp = None
                                self.attach_req_timestamp = None
                            self.pending_attach = True
                            self.attach_req_timestamp = log_item_dict['timestamp']
                            self.prev_log = log_xml

                        elif field.get('show') == '67':
                            # Attach complete, referring to http://niviuk.free.fr/lte_nas.php
                            print("ATT complete")
                            if self.attach_accept_timestamp:
                                delta = (log_item_dict['timestamp'] - self.attach_accept_timestamp).total_seconds()
                                if 0 <= delta <= self.threshold:
                                    self.accepting_attach = False
                                    self.attach_accept_timestamp = None
                                    self.timeouts = 0
                                    self.prev_log = None

                        elif field.get('show') == '69':
                            print("DET req")
                            # Detach request to network, referring to http://niviuk.free.fr/lte_nas.php
                            if self.pending_attach or self.accepting_attach:
                                delta = 0
                                if self.pending_attach:
                                    delta = (log_item_dict['timestamp'] - self.attach_req_timestamp).total_seconds()
                                else:
                                    delta = (log_item_dict['timestamp'] - self.attach_accept_timestamp).total_seconds()
                                if 0 <= delta <= self.threshold:
                                    self.kpi_measurements['failure_number']['DETACH'] += 1
                                    self.store_kpi("KPI_Retainability_ATTACH_DETACH_FAILURE", str(self.kpi_measurements['failure_number']['DETACH']), log_item_dict['timestamp'])
                                    self.accepting_attach = False
                                    self.pending_attach = False
                                    self.prev_log = None
                                    self.timeouts = 0
                                    self.attach_accept_timestamp = None
                                    self.attach_req_timestamp = None
        return 0