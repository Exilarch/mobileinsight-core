# Usage: python kpi-manager-test.py [dirname]
# Example 1: python kpi-manager-test.py auth_sample.mi2log 
# (For testing KPIs related to AUTH)
# Example 2: python kpi-manager-test.py attach_sample.mi2log 
# (For testing KPIs related to ATTACH)
# Example 3: python kpi-manager-test.py tau_sample.mi2log 
# (For testing KPIs related to TAU)
# Example 4: python kpi-manager-test.py detach_sample.mi2log 
# (For testing KPIs related to DETACH)

import sys
import os
from mobile_insight.monitor import OfflineReplayer
from mobile_insight.analyzer.kpi import KPIManager, KpiAnalyzer, IdentificationFrAnalyzer, SecurityModeControlFrAnalyzer, GutiReallocationFrAnalyzer, AuthFrAnalyzer, AttachFrAnalyzer, TauFrAnalyzer, DetachFrAnalyzer
import cProfile


def kpi_manager_example(path):
    """
    If running a large amount of logs, only run KPIs for one EMM procedure.
    """
    src = OfflineReplayer()
    src.set_input_path(path)

    kpi_manager = KPIManager()

    # kpi_manager.enable_kpi("KPI.Retainability.IDENTIFY_COLLISION_FAILURE")
    # kpi_manager.enable_kpi("KPI.Retainability.IDENTIFY_TRANSMISSION_TAU_FAILURE")
    # kpi_manager.enable_kpi("KPI.Retainability.IDENTIFY_TRANSMISSION_SERVICE_FAILURE")
    # kpi_manager.enable_kpi("KPI.Retainability.IDENTIFY_UNAVAILABLE_FAILURE")
    # kpi_manager.enable_kpi("KPI.Retainability.IDENTIFY_CONCURRENT_FAILURE")
    # kpi_manager.enable_kpi("KPI.Retainability.IDENTIFY_TIMEOUT_FAILURE")
    # kpi_manager.enable_kpi("KPI.Retainability.IDENTIFY_HANDOVER_FAILURE")

    # kpi_manager.enable_kpi("KPI.Retainability.SECURITY_TRANSMISSION_TAU_FAILURE")
    # kpi_manager.enable_kpi("KPI.Retainability.SECURITY_TRANSMISSION_SERVICE_FAILURE")
    # kpi_manager.enable_kpi("KPI.Retainability.SECURITY_TIMEOUT_FAILURE")
    # kpi_manager.enable_kpi("KPI.Retainability.SECURITY_COLLISION_FAILURE")
    # kpi_manager.enable_kpi("KPI.Retainability.SECURITY_HANDOVER_FAILURE")

    # kpi_manager.enable_kpi("KPI.Retainability.GUTI_TIMEOUT_FAILURE")
    # kpi_manager.enable_kpi("KPI.Retainability.GUTI_COLLISION_FAILURE")
    # kpi_manager.enable_kpi("KPI.Retainability.GUTI_HANDOVER_FAILURE")

    kpi_manager.enable_kpi("KPI.Retainability.AUTH_MAC_FAILURE")
    kpi_manager.enable_kpi("KPI.Retainability.AUTH_SYNCH_FAILURE")
    kpi_manager.enable_kpi("KPI.Retainability.AUTH_NON_EPS_FAILURE")
    kpi_manager.enable_kpi("KPI.Retainability.AUTH_EMM_FAILURE")
    kpi_manager.enable_kpi("KPI.Retainability.AUTH_TRANSMISSION_TAU_FAILURE")
    kpi_manager.enable_kpi("KPI.Retainability.AUTH_TRANSMISSION_SERVICE_FAILURE")
    kpi_manager.enable_kpi("KPI.Retainability.AUTH_TIMEOUT_FAILURE")
    kpi_manager.enable_kpi("KPI.Retainability.AUTH_HANDOVER_FAILURE")

    kpi_manager.enable_kpi("KPI.Retainability.ATTACH_PROTOCOL_ERROR_FAILURE")
    kpi_manager.enable_kpi("KPI.Retainability.ATTACH_DETACH_FAILURE")
    kpi_manager.enable_kpi("KPI.Retainability.ATTACH_CONCURRENT_FAILURE")
    kpi_manager.enable_kpi("KPI.Retainability.ATTACH_TIMEOUT_FAILURE")
    kpi_manager.enable_kpi("KPI.Retainability.ATTACH_EMM_FAILURE")

    kpi_manager.enable_kpi("KPI.Retainability.TAU_PROTOCOL_ERROR_FAILURE")
    kpi_manager.enable_kpi("KPI.Retainability.TAU_DETACH_FAILURE")
    kpi_manager.enable_kpi("KPI.Retainability.TAU_CONCURRENT_FAILURE")
    kpi_manager.enable_kpi("KPI.Retainability.TAU_TIMEOUT_FAILURE")
    kpi_manager.enable_kpi("KPI.Retainability.TAU_EMM_FAILURE")
    kpi_manager.enable_kpi("KPI.Retainability.TAU_HANDOVER_FAILURE")

    kpi_manager.enable_kpi("KPI.Retainability.DETACH_COLLISION_FAILURE")
    kpi_manager.enable_kpi("KPI.Retainability.DETACH_TIMEOUT_FAILURE")
    kpi_manager.enable_kpi("KPI.Retainability.DETACH_EMM_FAILURE")
    kpi_manager.enable_kpi("KPI.Retainability.DETACH_HANDOVER_FAILURE")

    kpi_manager.set_source(src)

    src.run()


if __name__ == '__main__':
    kpi_manager_example(sys.argv[1])



