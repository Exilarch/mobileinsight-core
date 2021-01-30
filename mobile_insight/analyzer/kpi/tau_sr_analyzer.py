#!/usr/bin/python
# Filename: tau_sr_analyzer.py
"""
tau_sr_analyzer.py
An KPI analyzer to monitor and manage dedicated bearer setup success rate

Author: Zhehui Zhang
"""

__all__ = ["TauSrAnalyzer"]

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
             '40': 'NO_EPS_ACTIVATED'}

class TauSrAnalyzer(KpiAnalyzer):
    """
    An KPI analyzer to monitor and manage tracking area update success rate
    """

    def __init__(self):
        KpiAnalyzer.__init__(self)

        self.cell_id = None

        self.kpi_measurements = {'success_number': {'TOTAL': 0}, \
                                 'total_number': {'TOTAL': 0},\
                                 'reject_number': {},\
                                 'failure_number': {'CONCURRENT': 0, 'PROTOCOL_ERROR': 0, 'TIMEOUT': 0, 'DETACH': 0, 'EMM': 0}}
        for cause_idx in [3, 6, 7] + list(range(9, 16)) + [22, 25, 40]:
            self.kpi_measurements['reject_number'][EMM_cause[str(cause_idx)]] = 0

        # print self.kpi_measurements

        # self.current_kpi = {'TOTAL': 0}

        self.register_kpi("Mobility", "TAU_SUC", self.__emm_sr_callback,
                          list(self.kpi_measurements['success_number'].keys()))
        self.register_kpi("Mobility", "TAU_SR", self.__emm_sr_callback)
        self.register_kpi("Mobility", "TAU_REQ", self.__emm_sr_callback,
                          list(self.kpi_measurements['total_number'].keys()))
        self.register_kpi("Mobility", "TAU_SR_LATENCY", self.__emm_sr_callback,
                          None)
        self.register_kpi("Retainability", "TAU_REJ", self.__emm_sr_callback,
                          list(self.kpi_measurements['reject_number'].keys()))

        for kpi in self.kpi_measurements["failure_number"]:
            self.register_kpi("Retainability", "TAU_" + kpi + "_FAILURE", self.__emm_sr_callback)

        self.prev_log = None
        self.T3430 = 15 # in WB-S1 mode, T3430 should be 77 seconds. Default, 15s, is assumed.
        self.T3450 = 6 # in WB-S1 mode, T3450 should be 18 seconds. Default value, 6s, is assumed.
        self.timeouts = 0
        self.pending_TAU = False
        self.accepting_TAU = False
        self.threshold = self.T3430 + 10 # keep an internal threshold between failure messages
        self.TAU_req_timestamp = None
        self.TAU_accept_timestamp = None

        # add callback function
        self.add_source_callback(self.__emm_sr_callback)

    def set_source(self,source):
        """
        Set the trace source. Enable the LTE ESM messages.

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
        cell_id = self.get_analyzer('TrackCellInfoAnalyzer').get_cur_cell_id()
        if cell_id != self.cell_id:
            self.cell_id = cell_id
            self.__clear_counters()

        if msg.type_id == "LTE_NAS_EMM_OTA_Incoming_Packet":
            log_item = msg.data.decode()
            log_item_dict = dict(log_item)
            if "Msg" in log_item_dict:
                log_xml = ET.XML(log_item_dict["Msg"])
                for field in log_xml.iter('field'):
                    if field.get("name") == "nas_eps.nas_msg_emm_type":
                        if field.get('show') == '69':
                            # Detach request to UE
                            if self.pending_TAU and self.TAU_req_timestamp:
                                for subfield in log_xml.iter("field"):
                                    detach_type = ""
                                    cause_idx = -1
                                    if subfield.get("showname") and "re-attach" in subfield.get("showname").lower():
                                        detach_type = subfield.get("showname").lower()
                                    elif subfield.get('name') == 'nas_eps.emm.cause':
                                        cause_idx = str(subfield.get('show'))
                                # failure case. detach with these conditions
                                if ("re-attach not required" in detach_type and cause_idx != 2) or ("re-attach required" in detach_type):
                                    self.kpi_measurements['failure_number']['DETACH'] += 1
                                    self.store_kpi("KPI_Retainability_TAU_DETACH_FAILURE", str(self.kpi_measurements['failure_number']['CONCURRENT']), log_item_dict['timestamp'])
                                    self.timeouts = 0
                                    self.pending_TAU = False
                                    self.prev_log = None
                                    self.TAU_req_timestamp = None
                        elif field.get('show') == '73':
                            print("TAU accept")
                            if self.accepting_TAU:
                                if self.TAU_accept_timestamp:
                                    delta = (log_item_dict['timestamp'] - self.TAU_accept_timestamp).total_seconds()
                                    if 0 <= delta <= self.threshold:
                                        self.timeouts += 1
                                    else:
                                        self.timeouts = 0
                                # if self.type in self.kpi_measurements['success_number']:
                                #     self.kpi_measurements['success_number'][self.type] += 1
                                #     self.store_kpi("KPI_Accessibility_ATTACH_SUC",
                                #                    self.kpi_measurements['success_number'], log_item_dict['timestamp'])
                                #     upload_dict = {
                                #         'total_number': self.kpi_measurements['total_number'],
                                #         'success_number': self.kpi_measurements['success_number']}
                                    # self.upload_kpi('KPI.Accessibility.ATTACH_SR', upload_dict)
                                # self.__calculate_kpi()
                                # self.store_kpi("KPI_Accessibility_ATTACH_SR_" + self.type, \
                                               # '{:.2f}'.format(self.current_kpi[self.type]), msg.timestamp)
                            if self.timeouts == 5:
                                self.kpi_measurements['failure_number']['TIMEOUT'] += 1
                                self.store_kpi("KPI_Retainability_TAU_TIMEOUT_FAILURE", str(self.kpi_measurements['failure_number']['TIMEOUT']), log_item_dict['timestamp'])
                                self.accepting_TAU = False
                                self.prev_log = None
                                self.timeouts = 0
                                self.TAU_accept_timestamp = None
                            self.accepting_TAU = True
                            self.TAU_accept_timestamp = log_item_dict['timestamp']
                            self.prev_log = log_xml
                            self.pending_TAU = False
                            self.TAU_req_timestamp = None
                            # self.kpi_measurements['success_number']['TOTAL'] += 1
                            # self.__calculate_kpi()
                            # self.log_info("TAU_SR: " + str(self.kpi_measurements))
                            # self.store_kpi("KPI_Mobility_TAU_SUC",
                            #             self.kpi_measurements['success_number'], log_item_dict['timestamp'])
                            # upload_dict = {
                            #     'total_number': self.kpi_measurements['total_number']['TOTAL'],
                            #     'success_number': self.kpi_measurements['success_number']['TOTAL']}
                            # self.upload_kpi('KPI.Mobility.TAU_SR', upload_dict)
                            # self.tau_req_flag = False

                            # TAU latency
                            # delta_time = (log_item_dict['timestamp']-self.tau_req_timestamp).total_seconds()
                            # if delta_time >= 0:
                            #     upload_dict = {'latency': delta_time}
                            #     self.upload_kpi("KPI.Mobility.TAU_SR_LATENCY", upload_dict)
                            # cause_idx = str(child_field.get('show'))
                            # if cause_idx in EMM_cause:
                            #     self.kpi_measurements['reject_number'][EMM_cause[cause_idx]] += 1
                            #     # self.log_info("TAU_SR: " + str(self.kpi_measurements))
                            #     self.store_kpi("KPI_Retainability_TAU_REJ",
                            #                    self.kpi_measurements['reject_number'], log_item_dict['timestamp'])
                            #     upload_dict = {
                            #         'total_number': self.kpi_measurements['total_number']['TOTAL'],
                            #         'reject_number': self.kpi_measurements['reject_number']}
                            #     # self.upload_kpi('KPI.Retainability.RRC_AB_REL', upload_dict, log_item_dict['timestamp'])
                            #     self.upload_kpi('KPI.Retainability.TAU_REJ', upload_dict)
                            # else:
                            #     self.log_warning("Unknown EMM cause for TAU reject: " + cause_idx)
                        # Tracking area update reject
                        elif field.get('show') == '75':
                            print("TAU reject")
                            for subfield in log_xml.iter('field'):
                                if subfield.get('name') == 'nas_eps.emm.cause':
                                    cause_idx = str(subfield.get('show'))
                                    protocol_errors = ['96', '99', '100', '111']
                                    normal_failures = ['3', '6', '7', '9', '10', '11', '12', '13', '14', '15', '25', '35', '40', '42']
                                    if cause_idx in protocol_errors:
                                        self.kpi_measurements['failure_number']['PROTOCOL_ERROR'] += 1
                                        self.store_kpi('KPI_Retainability_TAU_PROTOCOL_ERROR_FAILURE', str(self.kpi_measurements['failure_number']['PROTOCOL_ERROR']), log_item_dict['timestamp'])
                                    elif cause_idx == '22':
                                        for subfield in log_xml.iter('field'):
                                            if subfield.get('showname') and 'T3346' in subfield.get('showname'):
                                                self.kpi_measurements['failure_number']['EMM'] += 1
                                                self.store_kpi('KPI_Retainability_TAU_EMM_FAILURE', str(self.kpi_measurements['failure_number']['EMM']), log_item_dict['timestamp'])
                                                break
                                    elif cause_idx not in normal_failures:
                                        self.kpi_measurements['failure_number']['EMM'] += 1
                                        self.store_kpi('KPI_Retainability_TAU_EMM_FAILURE', str(self.kpi_measurements['failure_number']['EMM']), log_item_dict['timestamp'])
                                    else:
                                        self.log_warning("Unknown EMM cause: " + cause_idx)
                            self.pending_TAU = False
                            self.accepting_TAU = False
                            self.TAU_req_timestamp = None
                            self.TAU_accept_timestamp = None
                            self.prev_log = None
                            self.timeouts = 0

        elif msg.type_id == "LTE_NAS_EMM_OTA_Outgoing_Packet":
            log_item = msg.data.decode()
            log_item_dict = dict(log_item)
            if "Msg" in log_item_dict:
                log_xml = ET.XML(log_item_dict["Msg"])
                for field in log_xml.iter('field'):
                    if field.get("name") == "nas_eps.nas_msg_emm_type":
                        # Detach request
                        if field.get('show') == '69':
                            if self.pending_TAU:
                                # search for switch off
                                for subfield in log_xml.iter("field"):
                                    # failure case. detach with switch off field and pending ID.
                                    if subfield.get("showname") and "Switch off" in subfield.get("showname"):
                                        self.kpi_measurements["failure_number"]["DETACH"] += 1
                                        self.store_kpi("KPI_Retainability_TAU_DETACH_FAILURE", self.kpi_measurements["failure_number"]["DETACH"], log_item_dict["timestamp"])
                                        self.timeouts = 0
                                        self.pending_TAU = False
                                        self.prev_log = None
                                        self.TAU_req_timestamp = None
                                        self.accepting_TAU = False
                                        self.TAU_accept_timestamp = None
                                        break
                        # '72' indicates Tracking Area Update request
                        elif field.get('show') == '72':
                            print("TAU request")
                            if self.pending_TAU or self.accepting_TAU:
                                delta = 0
                                if self.pending_TAU:
                                    delta = (log_item_dict['timestamp'] - self.TAU_req_timestamp).total_seconds()
                                else:
                                    delta = (log_item_dict['timestamp'] - self.TAU_accept_timestamp).total_seconds()
                                if 0 <= delta <= self.threshold:
                                    prev_IE = {}
                                    curr_IE = {}
                                    # compile information elements
                                    for prev_field in self.prev_log.iter("field"):
                                        if prev_field.get("name") == "nas_eps.emm.esm_msg_cont":
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
                                        if field.get("name") == "nas_eps.emm.esm_msg_cont":
                                            curr_IE[field.get("show")] = field.get("showname")
                                        elif field.get("name") == "nas_eps.emm.type_of_id":
                                            curr_IE[field.get("show")] = field.get("showname")
                                        elif field.get("name") == "gsm_a.gm.gmm.ue_usage_setting":
                                            curr_IE[field.get("show")] = field.get("showname")
                                        elif field.get("show") == "EPS mobile identity":
                                            curr_IE[field.get("show")] = field.get("showname")
                                        elif field.get("show") == "UE network capability":
                                            curr_IE[field.get("show")] = field.get("showname")
                                        elif field.get("show") == "DRX parameter":
                                            curr_IE[field.get("show")] = field.get("showname")
                                    if prev_IE != curr_IE:
                                        self.kpi_measurements['failure_number']['CONCURRENT'] += 1
                                        self.store_kpi("KPI_Retainability_TAU_CONCURRENT_FAILURE", str(self.kpi_measurements['failure_number']['CONCURRENT']), log_item_dict['timestamp'])
                                        self.timeouts = 0
                                        self.pending_TAU = False
                                        self.accepting_TAU= False
                                        self.prev_log = None
                                        self.TAU_accept_timestamp = None
                                        self.TAU_req_timestamp = None
                            if self.TAU_req_timestamp and self.pending_TAU:
                                delta = (log_item_dict["timestamp"] - self.TAU_req_timestamp).total_seconds()
                                if 0 <= delta <= self.threshold:
                                    self.timeouts += 1
                                else:
                                    self.timeouts = 0
                            if self.timeouts == 5:
                                self.kpi_measurements['failure_number']['TIMEOUT'] += 1
                                self.store_kpi("KPI_Retainability_TAU_TIMEOUT_FAILURE", str(self.kpi_measurements['failure_number']['TIMEOUT']), log_item_dict['timestamp'])
                                self.timeouts = 0
                                self.pending_TAU = False
                                self.prev_log = None
                                self.TAU_req_timestamp = None
                                self.accepting_TAU = False
                                self.TAU_accept_timestamp = None
                            self.pending_TAU = True
                            self.TAU_req_timestamp = log_item_dict['timestamp']
                            self.prev_log = log_xml
                            self.store_kpi("KPI_Mobility_TAU_REQ",
                                           self.kpi_measurements['total_number'], log_item_dict['timestamp'])
                        # '74' means Tracking Area Update complete
                        elif field.get('show') == '74':
                            print("TAU complete")
                            if self.TAU_accept_timestamp:
                                delta = (log_item_dict['timestamp'] - self.TAU_accept_timestamp).total_seconds()
                                if 0 <= delta <= self.threshold:
                                    self.accepting_TAU = False
                                    self.TAU_accept_timestamp = None
                                    self.timeouts = 0
                                    self.prev_log = None
                                    self.pending_TAU = False
                                    self.TAU_req_timestamp = None






