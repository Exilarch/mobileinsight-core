#!/usr/bin/python
# Filename: guti_reallocation_fr_analyzer.py
"""
guti_reallocation_fr_analyzer.py
A KPI analyzer to monitor and manage GUTI reallocation failure rate

Author: Andrew Oeung

"""

__all__ = ["guti_reallocation_fr_analyzer"]

try:
    import xml.etree.cElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET
from .kpi_analyzer import KpiAnalyzer
import datetime

class GutiReallocationFrAnalyzer(KpiAnalyzer):
    """
    A KPI analyzer to monitor and manage GUTI reallocation failure rate
    """

    def __init__(self):
        KpiAnalyzer.__init__(self)

        self.cell_id = None

        self.kpi_measurements = {'failure_number': {'TIMEOUT': 0, 'COLLISION': 0}}

        for kpi in self.kpi_measurements["failure_number"]:
            self.register_kpi("Retainability", "GUTI_" + kpi + "_FAILURE", self.__emm_sr_callback)

        self.guti_timestamp = None
        self.prev_log = None
        self.T3450 = 6 # in WB-S1 mode, T3450 should be 24 seconds. Default value, 6s, is assumed.
        self.timeouts = 0
        self.pending_guti = False
        self.threshold = 30 # keep an internal threshold of 30 seconds between failure messages
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
                            if field.get('show') == '80':
                                print("GUTI request")
                                # check for retransmit
                                if self.pending_guti:
                                    if self.guti_timestamp:
                                        delta = (log_item_dict['timestamp'] - self.guti_timestamp).total_seconds()
                                    if 0 <= delta <= self.T3450:
                                        self.timeouts += 1
                                    else:
                                        self.timeouts = 0
                                if self.timeouts == 5:
                                    self.kpi_measurements['failure_number']['TIMEOUT'] += 1
                                    self.store_kpi("KPI_Retainability_GUTI_TIMEOUT_FAILURE", str(self.kpi_measurements['failure_number']['TIMEOUT']), log_item_dict['timestamp'])
                                    self.pending_guti = False
                                    self.prev_log = None
                                    self.timeouts = 0
                                self.guti_timestamp = log_item_dict['timestamp']
                                self.pending_guti = True
                                self.prev_log = log_xml
        elif msg.type_id == "LTE_NAS_EMM_OTA_Outgoing_Packet":
            log_item = msg.data.decode()
            log_item_dict = dict(log_item)
            if "Msg" in log_item_dict:
                log_xml = ET.XML(log_item_dict["Msg"])
                for field in log_xml.iter('field'):
                    if field.get("name") == "nas_eps.nas_msg_emm_type":
                        if field.get('show') == '65' or field.get('show') == '69' or field.get('show') == '72' or field.get('show') == '255':
                            if self.pending_guti:
                                if self.guti_timestamp:
                                    delta = (log_item_dict['timestamp'] - self.guti_timestamp).total_seconds()
                                    print("GUTI delta")
                                    print(delta)
                                    if 0 <= delta <= self.threshold:
                                        self.kpi_measurements['failure_number']['COLLISION'] += 1
                                        self.store_kpi("KPI_Retainability_GUTI_COLLISION_FAILURE", str(self.kpi_measurements['failure_number']['COLLISION']), log_item_dict['timestamp'])
                                        self.pending_guti = False
                                        self.prev_log = None
                                        self.timeouts = 0
                        # GUTI complete
                        elif field.get('show') == '81':
                            print("GUTI complete")
                            self.pending_guti = False
                            self.prev_log = None
                            self.timeouts = 0
                            self.guti_timestamp = None

        return 0