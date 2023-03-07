"""
This module contains the main class `FortiFetch` which orchastrates the
logic of the application.

"""

from typing import List, Dict, Optional
from db import firewall_db
from db import general_db


class FortiFetch:
    @staticmethod
    def update_all_devices():

        firewall_db.write_device_info()

        firewall_db.write_interface_info()

        firewall_db.write_address_info()

        firewall_db.write_address_group_info()

        firewall_db.write_application_info()

        firewall_db.write_av_info()

        firewall_db.write_dnsfilter_info()

        # Uncomment the following line to enable the internetservice info, this will take a long time since there is 1000+ entries
        # firewall_db.write_internetservice_info()

        firewall_db.write_ippool_info()

        firewall_db.write_ips_info()

        firewall_db.write_sslssh_info()

        firewall_db.write_vip_info()

        firewall_db.write_webfilter_info()

        firewall_db.write_trafficshapers_info()

        firewall_db.write_trafficpolicy_info()

        firewall_db.write_dns_info()

        firewall_db.write_static_route_info()

        firewall_db.write_policy_route_info()

        firewall_db.write_snmpv2_info()

        firewall_db.write_snmpv3_info()

        firewall_db.write_fortiguard_info()

        firewall_db.write_admin_info()

        firewall_db.write_adminprofile_info()

        firewall_db.write_fwpolicy_info()

        firewall_db.write_vpn_monitor_info()

    @staticmethod
    def execute_sql(sql: str, params: Optional[tuple] = None) -> List[Dict]:
        return general_db.execute_sql(sql, params)
