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

class SecurityModeControlFrAnalyzer(KpiAnalyzer):
    """
    An KPI analyzer to monitor and manage security mode control failure rate
    """

    def __init__(self):
        KpiAnalyzer.__init__(self)

        self.cell_id = None

        self.kpi_measurements = {'failure_number': {'TRANSMISSION_TAU': 0, 'TRANSMISSION_SERVICE': 0, 'TIMEOUT': 0, 'COLLISION': 0}}

        for kpi in self.kpi_measurements["failure_number"]:
            self.register_kpi("Retainability", "SECURITY_" + kpi + "_FAILURE", self.__emm_sr_callback)

        self.security_mode_timestamp = None
        self.prev_log = None
        self.T3460 = 6 # in WB-S1 mode, T3460 should be 24 seconds. Default value, 6s, is assumed.
        self.timeouts = 0
        self.pending_security_mode = False
        self.pending_service = False
        self.pending_TAU = False
        self.threshold = 30 # keep an internal threshold between failure messages
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
                            # service reject
                            elif field.get('show') == '78':
                                self.pending_service = False
                            # service accept
                            elif field.get('show') == '79':
                                self.pending_service = False
                            # sec mode request
                            elif field.get('show') == '93':
                                if self.pending_security_mode and self.pending_service:
                                    if self.security_mode_timestamp:
                                        delta = (log_item_dict['timestamp'] - self.security_mode_timestamp).total_seconds()
                                    if 0 <= delta <= self.threshold:
                                        self.kpi_measurements['failure_number']['TRANSMISSION_SERVICE'] += 1
                                        self.store_kpi("KPI_Retainability_SECURITY_TRANSMISSION_SERVICE_FAILURE", str(self.kpi_measurements['failure_number']['TRANSMISSION_SERVICE']), log_item_dict['timestamp'])
                                        self.pending_security_mode = False
                                        self.pending_service = False
                                        self.pending_TAU = False
                                        self.prev_log = None
                                        self.timeouts = 0
                                elif self.pending_security_mode and self.pending_TAU:
                                    if self.security_mode_timestamp:
                                        delta = (log_item_dict['timestamp'] - self.security_mode_timestamp).total_seconds()
                                    if 0 <= delta <= self.threshold:
                                        self.kpi_measurements['failure_number']['TRANSMISSION_TAU'] += 1
                                        self.store_kpi("KPI_Retainability_SECURITY_TRANSMISSION_TAU_FAILURE", str(self.kpi_measurements['failure_number']['TRANSMISSION_TAU']), log_item_dict['timestamp'])
                                        self.pending_security_mode = False
                                        self.pending_service = False
                                        self.pending_TAU = False
                                        self.prev_log = None
                                        self.timeouts = 0
                                # check for retransmit
                                elif self.pending_security_mode:
                                    if self.security_mode_timestamp:
                                        delta = (log_item_dict['timestamp'] - self.security_mode_timestamp).total_seconds()
                                    if 0 <= delta <= self.threshold:
                                        self.timeouts += 1
                                    else:
                                        self.timeouts = 0
                                if self.timeouts == 5:
                                    self.kpi_measurements['failure_number']['TIMEOUT'] += 1
                                    self.store_kpi("KPI_Retainability_SECURITY_TIMEOUT_FAILURE", str(self.kpi_measurements['failure_number']['TIMEOUT']), log_item_dict['timestamp'])
                                    self.pending_security_mode = False
                                    self.pending_service = False
                                    self.pending_TAU = False
                                    self.prev_log = None
                                    self.timeouts = 0
                                self.security_mode_timestamp = log_item_dict['timestamp']
                                self.pending_security_mode = True
                                self.prev_log = log_xml
        elif msg.type_id == "LTE_NAS_EMM_OTA_Outgoing_Packet":
            log_item = msg.data.decode()
            log_item_dict = dict(log_item)
            if "Msg" in log_item_dict:
                log_xml = ET.XML(log_item_dict["Msg"])
                for field in log_xml.iter('field'):
                    if field.get("name") == "nas_eps.nas_msg_emm_type":
                        if field.get('show') == '65' or field.get('show') == '255' or field.get('show') == '72':
                            if self.pending_security_mode:
                                if self.security_mode_timestamp:
                                    print("SEC delta")
                                    print(delta)
                                    delta = (log_item_dict['timestamp'] - self.security_mode_timestamp).total_seconds()
                                    if 0 <= delta <= self.threshold:
                                        self.kpi_measurements['failure_number']['COLLISION'] += 1
                                        self.store_kpi("KPI_Retainability_SECURITY_COLLISION_FAILURE", str(self.kpi_measurements['failure_number']['COLLISION']), log_item_dict['timestamp'])
                                        self.pending_security_mode = False
                                        self.pending_service = False
                                        self.pending_TAU = False
                                        self.prev_log = None
                                        self.timeouts = 0
                            if field.get('show') == '72' and not self.pending_security_mode:
                                self.pending_TAU = True
                        elif field.get('show') == '69':
                            if self.pending_security_mode:
                                if self.security_mode_timestamp:
                                    print("SEC delta")
                                    print(delta)
                                    delta = (log_item_dict['timestamp'] - self.security_mode_timestamp).total_seconds()
                                    if 0 <= delta <= self.threshold:
                                        for subfield in log_xml.iter("field"):
                                            if subfield.get("showname") and "Switch off" not in subfield.get("showname"):
                                                self.kpi_measurements['failure_number']['COLLISION'] += 1
                                                self.store_kpi("KPI_Retainability_SECURITY_COLLISION_FAILURE", str(self.kpi_measurements['failure_number']['COLLISION']), log_item_dict['timestamp'])
                                                self.pending_security_mode = False
                                                self.pending_service = False
                                                self.pending_TAU = False
                                                self.prev_log = None
                                                self.timeouts = 0
                        # TAU complete
                        elif field.get('show') == '74':
                            self.pending_TAU = False
                        # Security mode complete
                        elif field.get('show') == '94':
                            self.pending_security_mode = False
                            self.pending_service = False
                            self.pending_TAU = False
                            self.prev_log = None
                            self.timeouts = 0
                        # Security mode reject
                        elif field.get('show') == '95':
                            self.pending_security_mode = False
                            self.pending_service = False
                            self.pending_TAU = False
                            self.prev_log = None
                            self.timeouts = 0
                        # Service request
                        elif field.get('show') == '255' and not self.pending_security_mode:
                            self.pending_service = True

        return 0