#!/usr/bin/python
# Filename: detach_analyzer.py
"""
detach_analyzer.py
An KPI analyzer to monitor and manage detach procedure success rate
Author: Zhehui Zhang
"""

__all__ = ["DetachAnalyzer"]

try:
    import xml.etree.cElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET
from .kpi_analyzer import KpiAnalyzer

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

class DetachAnalyzer(KpiAnalyzer):
    """
    An KPI analyzer to monitor and manage detach failure rate
    """

    def __init__(self):
        KpiAnalyzer.__init__(self)

        self.cell_id = None

        self.kpi_measurements = {'success_number': {'EMERGENCY': 0, 'NORMAL': 0, 'COMBINED': 0}, \
                                 'total_number': {'EMERGENCY': 0, 'NORMAL': 0, 'COMBINED': 0}, \
                                 'reject_number': {}, \
                                 'failure_number': {'TIMEOUT': 0, 'COLLISION': 0, 'EMM': 0}}

        for cause_idx in [3, 6, 7, 8] + list(range(11, 16)) + [18, 19, 22, 25, 35]:
            self.kpi_measurements['reject_number'][EMM_cause[str(cause_idx)]] = 0

        self.register_kpi("Accessibility", "DETACH_SUC", self.__emm_sr_callback,
                          list(self.kpi_measurements['success_number'].keys()))
        self.register_kpi("Accessibility", "DETACH_REQ", self.__emm_sr_callback,
                          list(self.kpi_measurements['total_number'].keys()))
        self.register_kpi("Accessibility", "DETACH_SR", self.__emm_sr_callback)
        
        for kpi in self.kpi_measurements["failure_number"]:
          self.register_kpi("Retainability", "DETACH_" + kpi + "_FAILURE", self.__emm_sr_callback)

        self.type = None # record attach because of current attach procedure
        self.detach_req_timestamp = None
        self.T3421 = 15 # default 15, 45s in WB-S1 mode
        self.T3422 = 6 # default 6, 24s in WB-S1 mode
        self.pending_detach = False
        self.prev_log = None
        self.timeouts = 0
        self.threshold = self.T3421 + 10

        # add callback function
        self.add_source_callback(self.__emm_sr_callback)

    def set_source(self,source):
        """
        Set the trace source. Enable the LTE EMM messages.
        :param source: the trace source.
        :type source: trace collector
        """
        KpiAnalyzer.set_source(self,source)
        #enable LTE EMM logs
        source.enable_log("LTE_NAS_EMM_OTA_Incoming_Packet")
        source.enable_log("LTE_NAS_EMM_OTA_Outgoing_Packet")

    def __calculate_kpi(self):
        for type in self.current_kpi:
            if self.kpi_measurements['total_number'][type] != 0:
                self.current_kpi[type] = \
                    self.kpi_measurements['success_number'][type] / float(self.kpi_measurements['total_number'][type])
            else:
                self.current_kpi[type] = 0.00

    def __clear_counters(self):
        for key, value in self.kpi_measurements.items():
            if type(value) == type(1):
                self.kpi_measurements[key] = 0
            else:
                for sub_key, sub_value in value.items():
                    value[sub_key] = 0

    def __emm_sr_callback(self, msg):
        if msg.type_id == "LTE_NAS_EMM_OTA_Incoming_Packet":
            log_item = msg.data.decode()
            log_item_dict = dict(log_item)
            if "Msg" in log_item_dict:
                log_xml = ET.XML(log_item_dict["Msg"])
                for field in log_xml.iter('field'):
                    if field.get("name") == "nas_eps.nas_msg_emm_type":
                        # Detach request (Network initiated)
                        if field.get('show') == '69':
                            for subfield in log_xml.iter("field"):
                                if subfield.get('name') == 'nas_eps.emm.cause':
                                    cause_idx = str(subfield.get('show'))
                                    if cause_idx == "25":
                                        self.kpi_measurements['failure_number']['EMM'] += 1
                                        self.store_kpi('KPI_Retainability_DETACH_EMM_FAILURE', str(self.kpi_measurements['failure_number']['EMM']), log_item_dict['timestamp'])
                                        self.timeouts = 0
                                        break
                            if self.detach_req_timestamp:
                                delta = (log_item_dict['timestamp'] - self.detach_req_timestamp).total_seconds()
                                if 0 <= delta <= self.threshold:
                                    self.timeouts += 1
                                else:
                                    self.timeouts = 0
                            if self.timeouts == 5:
                                self.kpi_measurements['failure_number']['TIMEOUT'] += 1
                                self.store_kpi("KPI_Retainability_DETACH_TIMEOUT_FAILURE", str(self.kpi_measurements['failure_number']['TIMEOUT']), log_item_dict['timestamp'])
                                self.timeouts = 0
                                self.pending_detach = False
                                self.prev_log = None
                                self.detach_req_timestamp = None
                            self.pending_detach = True
                            self.detach_req_timestamp = log_item_dict['timestamp']
                            self.prev_log = log_xml
                        # Detach accept (UE initiated)
                        elif field.get('show') == '70':
                            self.pending_detach = False
                            self.prev_log = None
                            self.timeouts = 0
                            self.detach_req_timestamp = None
        elif msg.type_id == "LTE_NAS_EMM_OTA_Outgoing_Packet":
            log_item = msg.data.decode()
            log_item_dict = dict(log_item)
            if 'Msg' in log_item_dict:
                log_xml = ET.XML(log_item_dict['Msg'])
                for field in log_xml.iter('field'):
                    if field.get('name') == "nas_eps.nas_msg_emm_type":
                        # Attach request
                        if field.get('show') == '65':
                            if self.pending_detach and self.detach_req_timestamp:
                                for subfield in self.prev_log.iter("field"):
                                    detach_type = ""
                                    cause_idx = -1
                                    if subfield.get("showname"):
                                        if "re-attach" in subfield.get("showname").lower() or "imsi detach" in subfield.get("showname").lower():
                                            detach_type = subfield.get("showname").lower()
                                    elif subfield.get('name') == 'nas_eps.emm.cause':
                                        cause_idx = str(subfield.get('show'))
                                # failure case. detach with these conditions
                                if ("re-attach not required" in detach_type and cause_idx != 2) or ("imsi detach" in detach_type and cause_idx != 2) or ("re-attach required" in detach_type):
                                    self.kpi_measurements['failure_number']['COLLISION'] += 1
                                    self.store_kpi("KPI_Retainability_DETACH_COLLISION_FAILURE", str(self.kpi_measurements['failure_number']['COLLISION']), log_item_dict['timestamp'])
                                    self.timeouts = 0
                                    self.pending_detach = False
                                    self.prev_log = None
                                    self.detach_req_timestamp = None
                        # Detach request (UE initiated)
                        elif field.get('show') == '69':
                            if self.detach_req_timestamp:
                                delta = (log_item_dict['timestamp'] - self.detach_req_timestamp).total_seconds()
                                if 0 <= delta <= self.threshold:
                                    self.timeouts += 1
                                else:
                                    self.timeouts = 0
                            if self.timeouts == 5:
                                self.kpi_measurements['failure_number']['TIMEOUT'] += 1
                                self.store_kpi("KPI_Retainability_DETACH_TIMEOUT_FAILURE", str(self.kpi_measurements['failure_number']['TIMEOUT']), log_item_dict['timestamp'])
                                self.timeouts = 0
                                self.pending_detach = False
                                self.prev_log = None
                                self.detach_req_timestamp = None
                            self.pending_detach = True
                            self.detach_req_timestamp = log_item_dict['timestamp']
                            self.prev_log = log_xml
                        # Detach accept (Network initiated)
                        elif field.get('show') == '70':
                            self.pending_detach = False
                            self.prev_log = None
                            self.timeouts = 0
                            self.detach_req_timestamp = None
                        # Tracking Area Update request
                        elif field.get('show') == '72':
                            if self.pending_detach and self.detach_req_timestamp:
                                for subfield in self.prev_log.iter("field"):
                                    detach_type = ""
                                    cause_idx = -1
                                    if subfield.get("showname"):
                                        if "re-attach not required" in subfield.get("showname").lower() or "imsi detach" in subfield.get("showname").lower():
                                            detach_type = subfield.get("showname").lower()
                                    elif subfield.get('name') == 'nas_eps.emm.cause':
                                        cause_idx = str(subfield.get('show'))
                                # failure case. detach with these conditions
                                if ("re-attach not required" in detach_type and cause_idx == 2) or ("imsi detach" in detach_type):
                                    self.kpi_measurements['failure_number']['COLLISION'] += 1
                                    self.store_kpi("KPI_Retainability_DETACH_COLLISION_FAILURE", str(self.kpi_measurements['failure_number']['COLLISION']), log_item_dict['timestamp'])
                                    self.timeouts = 0
                                    self.pending_detach = False
                                    self.prev_log = None
                                    self.detach_req_timestamp = None

        return 0