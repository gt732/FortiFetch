"""
This module contains all the backend functions to write
firewall data to each table in the database.
"""

# import modules
from rich import print
from data_cleaning.network.clean_network_data import *
from data_cleaning.policy_object.clean_policy_address import *
from data_cleaning.security_profiles.clean_security_profile import *
from data_cleaning.system.clean_device_data import *
from data_cleaning.user_authentication.clean_user_data import *
from data_cleaning.vpn.clean_vpn_data import *
from db.db import get_db
from db.models import *


def write_device_info():
    """
    Get the device information from the clean_device_data() function and
    Write device information to the `device` table in the database
    """
    print("[bold blue]Updating devices in database[/bold blue] :wrench:")
    device_info = clean_device_data()

    with get_db() as db:
        db.query(Device).delete()

        for device in device_info:
            new_device = Device(
                hostname=device["hostname"],
                version=device["version"],
                model=device["model"],
            )
            db.add(new_device)

        db.commit()

    print(
        "[bold green]Device information updated successfully[/bold green] :white_check_mark:"
    )
    print("*" * 80)


def write_adminprofile_info():
    """
    Get the admin profile information from the clean_admin_profile_data() function and
    Write admin profile information to the `adminprofile` table in the database
    """
    print("[bold blue]Updating admin profile in database[/bold blue] :wrench:")
    admin_profile_info = clean_admin_profile_data()

    with get_db() as db:

        db.query(AdminProfile).delete()

        for admin_profile in admin_profile_info:
            hostname = admin_profile["hostname"]
            device = db.query(Device).filter(Device.hostname == hostname).one()

            new_admin_profile = AdminProfile(
                device_id=device.device_id,
                name=admin_profile["name"],
                scope=admin_profile["scope"],
                comments=admin_profile["comments"],
                ftviewgrp=admin_profile["ftviewgrp"],
                authgrp=admin_profile["authgrp"],
                sysgrp=admin_profile["sysgrp"],
                netgrp=admin_profile["netgrp"],
                loggrp=admin_profile["loggrp"],
                fwgrp=admin_profile["fwgrp"],
                vpngrp=admin_profile["vpngrp"],
                utmgrp=admin_profile["utmgrp"],
                wanoptgrp=admin_profile["wanoptgrp"],
                wifi=admin_profile["wifi"],
                netgrp_permission=admin_profile["netgrp_permission"],
                sysgrp_permission=admin_profile["sysgrp_permission"],
                fwgrp_permission=admin_profile["fwgrp_permission"],
                loggrp_permission=admin_profile["loggrp_permission"],
                utmgrp_permission=admin_profile["utmgrp_permission"],
                admintimeout_override=admin_profile["admintimeout_override"],
                admintimeout=admin_profile["admintimeout"],
                systemdiagnostics=admin_profile["systemdiagnostics"],
                system_execute_ssh=admin_profile["system_execute_ssh"],
                system_execute_telnet=admin_profile["system_execute_telnet"],
            )
            db.add(new_admin_profile)

        db.commit()

    print(
        "[bold green]Admin profile information updated successfully[/bold green] :white_check_mark:"
    )
    print("*" * 80)


def write_admin_info():
    """
    Get the admin information from the clean_admin_data() function and
    Write admin information to the `admin` table in the database
    """
    print("[bold blue]Updating admin in database[/bold blue] :wrench:")
    admin_info = clean_admin_data()

    with get_db() as db:

        db.query(Admin).delete()

        for admin in admin_info:
            device_hostname = admin["hostname"]
            device = db.query(Device).filter(Device.hostname == device_hostname).one()

            new_admin = Admin(
                device_id=device.device_id,
                name=admin["name"],
                wildcard=admin["wildcard"],
                remote_auth=admin["remote-auth"],
                remote_group=admin["remote-group"],
                trusthost1=admin["trusthost1"],
                trusthost2=admin["trusthost2"],
                trusthost3=admin["trusthost3"],
                trusthost4=admin["trusthost4"],
                trusthost5=admin["trusthost5"],
                trusthost6=admin["trusthost6"],
                trusthost7=admin["trusthost7"],
                trusthost8=admin["trusthost8"],
                trusthost9=admin["trusthost9"],
                trusthost10=admin["trusthost10"],
                ip6_trusthost1=admin["ip6-trusthost1"],
                ip6_trusthost2=admin["ip6-trusthost2"],
                ip6_trusthost3=admin["ip6-trusthost3"],
                ip6_trusthost4=admin["ip6-trusthost4"],
                ip6_trusthost5=admin["ip6-trusthost5"],
                ip6_trusthost6=admin["ip6-trusthost6"],
                ip6_trusthost7=admin["ip6-trusthost7"],
                ip6_trusthost8=admin["ip6-trusthost8"],
                ip6_trusthost9=admin["ip6-trusthost9"],
                ip6_trusthost10=admin["ip6-trusthost10"],
                accprofile=admin["accprofile"],
                allow_remove_admin_session=admin["allow-remove-admin-session"],
                comments=admin["comments"],
                vdoms=admin["vdoms"],
                force_password_change=admin["force-password-change"],
                two_factor=admin["two-factor"],
                two_factor_authentication=admin["two-factor-authentication"],
                two_factor_notification=admin["two-factor-notification"],
            )
            db.add(new_admin)

        db.commit()

    print(
        "[bold green]Admin information updated successfully[bold green] :white_check_mark:"
    )
    print("*" * 80)


def write_fortiguard_info():
    """
    Get the fortiguard information from the clean_fortiguard_data() function and
    Write fortiguard information to the `fortiguard` table in the database
    """
    print("[bold blue]Updating fortiguard in database[/bold blue] :wrench:")
    fortiguard_info = clean_fortiguard_data()

    with get_db() as db:
        db.query(FortiGuard).delete()

        for device in fortiguard_info:
            hostname = device["hostname"]
            device_obj = db.query(Device).filter(Device.hostname == hostname).one()

            new_fortiguard = FortiGuard(
                device_id=device_obj.device_id,
                fortiguard_anycast=device["fortiguard_anycast"],
                fortiguard_anycast_source=device["fortiguard_anycast_source"],
                protocol=device["protocol"],
                port=device["port"],
                service_account_id=device["forti_forti_service_account_id"],
                load_balace_servers=device["forti_forti_load_balace_servers"],
                auto_join_forticloud=device["forti_forti_auto_join_forticloud"],
                update_server_location=device["forti_forti_update_server_location"],
                sandbox_inline_scan=device["forti_sandbox_inline_scan"],
                update_ffdb=device["forti_update_ffdb"],
                update_uwdb=device["forti_update_uwdb"],
                update_extdb=device["forti_update_extdb"],
                update_build_proxy=device["forti_update_build_proxy"],
                persistent_connection=device["forti_persistent_connection"],
                vdom=device["forti_vdom"],
                auto_firmware_upgrade=device["forti_auto_firmware_upgrade"],
                auto_firmware_upgrade_day=device["forti_auto_firmware_upgrade_day"],
                auto_firmware_upgrade_start_hour=device[
                    "forti_auto_firmware_upgrade_start_hour"
                ],
                auto_firmware_upgrade_end_hour=device[
                    "forti_auto_firmware_upgrade_end_hour"
                ],
                antispam_force_off=device["forti_antispam_force_off"],
                antispam_cache=device["forti_antispam_cache"],
                antispam_cache_ttl=device["forti_antispam_cache_ttl"],
                antispam_cache_mpercent=device["forti_antispam_cache_mpercent"],
                antispam_license=device["forti_antispam_license"],
                antispam_expiration=device["forti_antispam_expiration"],
                antispam_timeout=device["forti_antispam_timeout"],
                outbreak_prevention_force_off=device[
                    "forti_outbreak_prevention_force_off"
                ],
                outbreak_prevention_cache=device["forti_outbreak_prevention_cache"],
                outbreak_prevention_cache_ttl=device[
                    "forti_outbreak_prevention_cache_ttl"
                ],
                outbreak_prevention_cache_mpercent=device[
                    "forti_outbreak_prevention_cache_mpercent"
                ],
                outbreak_prevention_license=device["forti_outbreak_prevention_license"],
                outbreak_prevention_expiration=device[
                    "forti_outbreak_prevention_expiration"
                ],
                outbreak_prevention_timeout=device["forti_outbreak_prevention_timeout"],
                webfilter_force_off=device["forti_webfilter_force_off"],
                webfilter_cache=device["forti_webfilter_cache"],
                webfilter_cache_ttl=device["forti_webfilter_cache_ttl"],
                webfilter_license=device["forti_webfilter_license"],
                webfilter_expiration=device["forti_webfilter_expiration"],
                webfilter_timeout=device["forti_webfilter_timeout"],
                sdns_server_ip=device["forti_sdns_server_ip"],
                sdns_server_port=device["forti_sdns_server_port"],
                anycast_sdns_server_ip=device["forti_anycast_sdns_server_ip"],
                anycast_sdns_server_port=device["forti_anycast_sdns_server_port"],
                sdns_options=device["forti_sdns_options"],
                source_ip=device["forti_source_ip"],
                source_ip6=device["forti_source_ip6"],
                proxy_server_ip=device["forti_proxy_server_ip"],
                proxy_server_port=device["forti_proxy_server_port"],
                proxy_username=device["forti_proxy_username"],
                proxy_password=device["forti_proxy_password"],
                ddns_server_ip=device["forti_ddns_server_ip"],
                ddns_server_ip6=device["forti_ddns_server_ip6"],
                ddns_server_port=device["forti_ddns_server_port"],
                interface_select_method=device["forti_interface_select_method"],
                interface=device["forti_interface"],
            )
            db.add(new_fortiguard)

        db.commit()

    print(
        "[bold green]Fortiguard information updated successfully[/bold green] :white_check_mark:"
    )
    print("*" * 80)


def write_interface_info():
    """
    Get the interface information from the clean_interface_data() function and
    write interface information to the `interface` table in the database
    """
    print("[bold blue]Updating interfaces in database[/bold blue] :wrench:")
    interface_info = clean_interface_data()

    with get_db() as db:
        db.query(Interface).delete()
        for interface in interface_info:
            hostname = interface["hostname"]
            device = db.query(Device).filter(Device.hostname == hostname).one()

            new_interface = Interface(
                device_id=device.device_id,
                name=interface["name"],
                type=interface["type"],
                ip=interface["ip"],
                mtu=interface["mtu"],
                mode=interface["mode"],
                status=interface["status"],
                allowaccess=interface["allowaccess"],
                vdom=interface["vdom"],
            )
            db.add(new_interface)
        db.commit()

    print(
        "[bold green]Interface information updated successfully[/bold green] :white_check_mark:"
    )
    print("*" * 80)


def write_address_info():
    """
    Get the address information from the clean_address_data() function and
    write address information to the `address` table in the database
    """
    print("[bold blue]Updating addresses in database[/bold blue] :wrench:")
    address_info = clean_address_data()

    with get_db() as db:
        db.query(Address).delete()
        for address in address_info:
            hostname = address["hostname"]
            device = db.query(Device).filter(Device.hostname == hostname).one()

            new_address = Address(
                device_id=device.device_id,
                name=address["name"],
                associated_interface=address["associated_interface"],
                country=address["country"],
                end_ip=address["end_ip"],
                fqdn=address["fqdn"],
                start_ip=address["start_ip"],
                subnet=address["subnet"],
                address_type=address["address_type"],
            )
            db.add(new_address)
        db.commit()

    print(
        "[bold green]Address information updated successfully[/bold green] :white_check_mark:"
    )
    print("*" * 80)


def write_address_group_info():
    """
    Get the address group information from the clean_address_group_data() function and
    write address group information to the `addressgroup` table in the database
    """
    print("[bold blue]Updating address group in database[/bold blue] :wrench:")
    address_info = clean_address_group_data()
    with get_db() as db:
        db.query(AddressGroup).delete()
        for address in address_info:
            hostname = address["hostname"]
            device = db.query(Device).filter(Device.hostname == hostname).one()

            new_address_group = AddressGroup(
                device_id=device.device_id,
                name=address["name"],
                member=address["member"],
            )
            db.add(new_address_group)
        db.commit()

    print(
        "[bold green]Address group information updated successfully[/bold green] :white_check_mark:"
    )
    print("*" * 80)


def write_application_info():
    """
    Get the application profile information from the clean_application_data() function and
    write application profile information to the `appprofile` table in the database
    """
    print("[bold blue]Updating application profile in database[/bold blue] :wrench:")
    application_info = clean_application_data()
    with get_db() as db:
        db.query(AppProfile).delete()
        for application in application_info:
            hostname = application["hostname"]
            device = db.query(Device).filter(Device.hostname == hostname).one()

            new_app_profile = AppProfile(
                device_id=device.device_id,
                name=application["name"],
                comment=application["comment"],
                entries=application["entries"],
            )
            db.add(new_app_profile)
        db.commit()

    print(
        "[bold green]Application profile information updated successfully[/bold green] :white_check_mark:"
    )
    print("*" * 80)


def write_av_info():
    """
    Get the antivirus profile information from the clean_av_data() function and
    write antivirus profile information to the `avprofile` table in the database.
    """
    print("[bold blue]Updating antivirus profile in database[/bold blue] :wrench:")
    av_info = clean_av_data()

    with get_db() as db:
        db.query(AvProfile).delete()
        for av in av_info:
            hostname = av["hostname"]
            device = db.query(Device).filter(Device.hostname == hostname).one()

            new_av_profile = AvProfile(
                device_id=device.device_id,
                name=av["name"],
                comment=av["comment"],
                http=av["http"],
                ftp=av["ftp"],
                imap=av["imap"],
                pop3=av["pop3"],
                smtp=av["smtp"],
                nntp=av["nntp"],
                mapi=av["mapi"],
                ssh=av["ssh"],
                cifs=av["cifs"],
                nac_quar=av["nac_quar"],
                content_disarm=av["content_disarm"],
            )
            db.add(new_av_profile)
        db.commit()

    print(
        "[bold green]Antivirus profile information updated successfully[/bold green] :white_check_mark:"
    )
    print("*" * 80)


def write_dns_info():
    """
    Get the DNS information from the clean_dns_data() function and
    write DNS information to the `dns` table in the database.
    """
    print("[bold blue]Updating DNS data in database[/bold blue] :wrench:")
    cleaned_data = clean_dns_data()

    with get_db() as db:
        db.query(DNS).delete()
        for dns in cleaned_data:
            hostname = dns["hostname"]
            device = db.query(Device).filter(Device.hostname == hostname).one()

            new_dns = DNS(
                device_id=device.device_id,
                primary_dns=dns["dns_primary"],
                secondary_dns=dns["dns_secondary"],
                protocol=dns["protocol"],
                ssl_certificate=dns["ssl_certificate"],
                server_hostname=dns["server_hostname"],
                domain=dns["domain"],
                ip6_primary=dns["ip6_primary"],
                ip6_secondary=dns["ip6_secondary"],
                dns_timeout=dns["timeout"],
                retry=dns["retry"],
                cache_limit=dns["cache_limit"],
                cache_ttl=dns["cache_ttl"],
                source_ip=dns["source_ip"],
                interface_select_method=dns["interface_select_method"],
                interface=dns["interface"],
                server_select_method=dns["server_select_method"],
                alt_primary=dns["alt_primary"],
                alt_secondary=dns["alt_secondary"],
                log_fqdn=dns["log_fqdn"],
            )
            db.add(new_dns)
        db.commit()

    print("[bold green]DNS data updated successfully[/bold green] :white_check_mark:")
    print("*" * 80)


def write_static_route_info():
    """
    Get the static route information from the clean_static_route_data() function and
    write static route information to the `staticroute` table in the database.
    """
    print("[bold blue]Updating static route data in database[/bold blue] :wrench:")
    cleaned_data = clean_static_route_data()
    with get_db() as db:
        db.query(StaticRoute).delete()
        for route in cleaned_data:

            hostname = route["hostname"]
            device = db.query(Device).filter(Device.hostname == hostname).one()

            new_static_route = StaticRoute(
                device_id=device.device_id,  # assign the Device object to the device field
                seq_num=route["seq_num"],
                status=route["status"],
                dst=route["dst"],
                src=route["src"],
                gateway=route["gateway"],
                distance=route["distance"],
                weight=route["weight"],
                priority=route["priority"],
                interface=route["device"],
                comment=route["comment"],
                blackhole=route["blackhole"],
                dynamic_gateway=route["dynamic_gateway"],
                sdwan_zone=route["sdwan_zone"],
                dstaddr=route["dstaddr"],
                internet_service=route["internet_service"],
                internet_service_custom=route["internet_service_custom"],
                tag=route["tag"],
                vrf=route["vrf"],
                bfd=route["bfd"],
            )
            db.add(new_static_route)
        db.commit()

    print(
        "[bold green]Static route data updated successfully[/bold green] :white_check_mark:"
    )
    print("*" * 80)


def write_policy_route_info():
    """
    Get the policy route information from the clean_policy_route_data() function and
    write policy route information to the `policyroute` table in the database.
    """
    print("[bold blue]Updating policy route data in database[/bold blue] :wrench:")
    cleaned_data = clean_policy_route_data()

    with get_db() as db:
        db.query(PolicyRoute).delete()
        for route in cleaned_data:

            hostname = route["hostname"]
            device = db.query(Device).filter(Device.hostname == hostname).one()

            new_policy_route = PolicyRoute(
                device_id=device.device_id,  # assign the Device object to the device field
                seq_num=route["seq_num"],
                input_device=route["input_device"],
                input_device_negate=route["input_device_negate"],
                src=route["src"],
                srcaddr=route["srcaddr"],
                src_negate=route["src_negate"],
                dst=route["dst"],
                dstaddr=route["dstaddr"],
                dst_negate=route["dst_negate"],
                action=route["action"],
                protocol=route["protocol"],
                start_port=route["start_port"],
                end_port=route["end_port"],
                start_source_port=route["start_source_port"],
                end_source_port=route["end_source_port"],
                gateway=route["gateway"],
                output_device=route["output_device"],
                status=route["status"],
                comments=route["comments"],
                internet_service_id=route["internet_service_id"],
                internet_service_custom=route["internet_service_custom"],
            )
            db.add(new_policy_route)
        db.commit()

    print(
        "[bold green]Policy route data updated successfully[/bold green] :white_check_mark:"
    )
    print("*" * 80)


def write_snmpv2_info():
    """
    Get the snmpv2 information from the clean_snmpv2_data() function and
    write snmpv2 information to the `snmpv2` table in the database.
    """
    print("[bold blue]Updating SNMPv2 data in database[/bold blue] :wrench:")
    cleaned_data = clean_snmpv2_data()

    with get_db() as db:
        db.query(SnmpV2).delete()
        for snmp in cleaned_data:
            hostname = snmp["hostname"]
            device = db.query(Device).filter(Device.hostname == hostname).one()

            new_snmpv2 = SnmpV2(
                device_id=device.device_id,
                id=snmp["id"],
                name=snmp["name"],
                status=snmp["status"],
                host=snmp["host"],
                host6=snmp["host6"],
                query_v1_status=snmp["query_v1_status"],
                query_v1_port=snmp["query_v1_port"],
                query_v2c_status=snmp["query_v2c_status"],
                query_v2c_port=snmp["query_v2c_port"],
                query_trap_v1_status=snmp["query_trap_v1_status"],
                query_trap_v1_rport=snmp["query_trap_v1_rport"],
                query_trap_v2c_status=snmp["query_trap_v2c_status"],
                query_trap_v2c_lport=snmp["query_trap_v2c_lport"],
                query_trap_v2c_rport=snmp["query_trap_v2c_rport"],
                events=snmp["events"],
                vdoms=snmp["vdoms"],
            )
            db.add(new_snmpv2)
        db.commit()

    print(
        "[bold green]SNMPv2 data updated successfully[/bold green] :white_check_mark:"
    )
    print("*" * 80)


def write_snmpv3_info():
    """
    Get the snmpv3 information from the clean_snmpv3_data() function and
    write snmpv3 information to the `snmpv3` table in the database.
    """
    print("[bold blue]Updating SNMPv3 data in database[/bold blue] :wrench:")
    cleaned_data = clean_snmpv3_data()

    with get_db() as db:
        db.query(Snmpv3).delete()
        for snmp in cleaned_data:
            hostname = snmp["hostname"]
            device = db.query(Device).filter(Device.hostname == hostname).one()

            new_snmpv3 = Snmpv3(
                device_id=device.device_id,
                name=snmp["name"],
                status=snmp["status"],
                trap_status=snmp["trap_status"],
                trap_lport=snmp["trap_lport"],
                trap_rport=snmp["trap_rport"],
                queries=snmp["queries"],
                query_port=snmp["query_port"],
                notify_hosts=snmp["notify_hosts"],
                notify_hosts6=snmp["notify_hosts6"],
                source_ip=snmp["source_ip"],
                source_ipv6=snmp["source_ipv6"],
                events=snmp["events"],
                vdoms=snmp["vdoms"],
                security_level=snmp["security_level"],
                auth_proto=snmp["auth_proto"],
                priv_proto=snmp["priv_proto"],
                priv_pwd=snmp["priv_pwd"],
            )
            db.add(new_snmpv3)
        db.commit()

    print(
        "[bold green]SNMPv3 data updated successfully[/bold green] :white_check_mark:"
    )
    print("*" * 80)


def write_dnsfilter_info():
    """
    Get the dnsfilter profile information from the clean_dnsfilter_data() function and
    write dnsfilter profile information to the `dnsprofile` table in the database.
    """
    print("[bold blue]Updating dnsprofile profile in database[/bold blue] :wrench:")
    cleaned_data = clean_dnsfilter_data()

    with get_db() as db:
        db.query(DnsProfile).delete()
        for profile in cleaned_data:
            hostname = profile["hostname"]
            device = db.query(Device).filter(Device.hostname == hostname).one()

            new_dns_profile = DnsProfile(
                device_id=device.device_id,
                name=profile["name"],
                comment=profile["comment"],
                domain_filter=profile["domain_filter"],
                ftgd_dns=profile["ftgd_dns"],
                block_botnet=profile["block_botnet"],
                safe_search=profile["safe_search"],
                youtube_restrict=profile["youtube_restrict"],
            )
            db.add(new_dns_profile)
        db.commit()

    print(
        "[bold green]Dnsprofile profile information updated successfully[/bold green] :white_check_mark:"
    )
    print("*" * 80)


def write_internetservice_info():
    """
    Get the internet service information from the clean_internetservice_data() function and
    write internet service information to the `internetservice` table in the database.
    """
    print("[bold blue]Updating internet service data in database[/bold blue] :wrench:")
    cleaned_data = clean_internetservice_data()

    with get_db() as db:
        db.query(InternetService).delete()
        for service in cleaned_data:
            hostname = service["hostname"]
            device = db.query(Device).filter(Device.hostname == hostname).one()

            new_internetservice = InternetService(
                device_id=device.device_id,
                name=service["name"],
                type=service["type"],
            )
            db.add(new_internetservice)
        db.commit()

    print(
        "[bold green]Internet service data updated successfully[/bold green] :white_check_mark:"
    )
    print("*" * 80)


def write_ippool_info():
    """
    Get the ippool information from the clean_ippool_data() function and
    write ippool information to the `ippool` table in the database.
    """
    print("[bold blue]Updating ippool data in database[/bold blue] :wrench:")
    cleaned_data = clean_ippool_data()

    with get_db() as db:
        db.query(IpPool).delete()
        for pool in cleaned_data:
            hostname = pool["hostname"]
            device = db.query(Device).filter(Device.hostname == hostname).one()

            new_ippool = IpPool(
                device_id=device.device_id,
                name=pool["name"],
                type=pool["type"],
                start_ip=pool["startip"],
                end_ip=pool["endip"],
                startport=pool["startport"],
                endport=pool["endport"],
                source_start_ip=pool["source_startip"],
                source_end_ip=pool["source_endip"],
                arp_reply=pool["arp_reply"],
                arp_intf=pool["arp_intf"],
                associated_interface=pool["associated_interface"],
                comments=pool["comments"],
            )
            db.add(new_ippool)
        db.commit()

    print(
        "[bold green]Ippool data updated successfully[/bold green] :white_check_mark:"
    )
    print("*" * 80)


def write_ips_info():
    """
    Get the ips profile information from the clean_ips_data() function and
    write ips profile information to the `ipsprofile` table in the database.
    """
    print("[bold blue]Updating IPS profile data in database[/bold blue] :wrench:")
    cleaned_data = clean_ips_data()

    with get_db() as db:
        db.query(IpsProfile).delete()
        for profile in cleaned_data:
            hostname = profile["hostname"]
            device = db.query(Device).filter(Device.hostname == hostname).one()

            new_ips_profile = IpsProfile(
                device_id=device.device_id,
                name=profile["name"],
                comment=profile["comment"],
                block_malicious_url=profile["block_malicious_url"],
                scan_botnet_connections=profile["scan_botnet_connections"],
                extended_log=profile["extended_log"],
                entries=profile["entries"],
            )
            db.add(new_ips_profile)
        db.commit()

    print(
        "[bold green]IPS profile data updated successfully[/bold green] :white_check_mark:"
    )
    print("*" * 80)


def write_sslssh_info():
    """
    Get the ssl/ssh profile information from the clean_sslssh_data() function and
    write ssl/ssh profile information to the `sslsshprofile` table in the database.
    """
    print("[bold blue]Updating SSL/SSH profile data in database[/bold blue] :wrench:")
    cleaned_data = clean_sslssh_data()

    with get_db() as db:
        db.query(SslSshProfile).delete()
        for profile in cleaned_data:
            hostname = profile["hostname"]
            device = db.query(Device).filter(Device.hostname == hostname).one()

            new_sslssh_profile = SslSshProfile(
                device_id=device.device_id,
                name=profile["name"],
                comment=profile["comment"],
                ssl=profile["ssl"],
                https=profile["https"],
                ftps=profile["ftps"],
                imaps=profile["imaps"],
                pop3s=profile["pop3s"],
                smtps=profile["smtps"],
                ssh=profile["ssh"],
                dot=profile["dot"],
                allowlist=profile["allowlist"],
                block_blocklisted_certificates=profile[
                    "block_blocklisted_certificates"
                ],
                ssl_exempt=profile["ssl_exempt"],
                ssl_exemption_ip_rating=profile["ssl_exemption_ip_rating"],
                ssl_server=profile["ssl_server"],
                caname=profile["caname"],
                mapi_over_https=profile["mapi_over_https"],
                rpc_over_https=profile["rpc_over_https"],
                untrusted_caname=profile["untrusted_caname"],
            )
            db.add(new_sslssh_profile)
        db.commit()

    print(
        "[bold green]SSL/SSH profile data updated successfully[/bold green] :white_check_mark:"
    )
    print("*" * 80)


def write_vip_info():
    """
    Get the vip profile information from the clean_vip_data() function and
    write vip profile information to the `vip` table in the database.
    """
    print("[bold blue]Updating VIP profile data in database[/bold blue] :wrench:")
    cleaned_data = clean_vip_data()

    with get_db() as db:
        db.query(Vip).delete()
        for vip in cleaned_data:
            hostname = vip["hostname"]
            device = db.query(Device).filter(Device.hostname == hostname).one()

            new_vip = Vip(
                device_id=device.device_id,
                name=vip["name"],
                comment=vip["comment"],
                type=vip["type"],
                ext_ip=vip["extip"],
                ext_addr=vip["extaddr"],
                nat44=vip["nat44"],
                mapped_ip=vip["mappedip"],
                mapped_addr=vip["mapped_addr"],
                ext_intf=vip["extintf"],
                arp_reply=vip["arp_reply"],
                portforward=vip["portforward"],
                status=vip["status"],
                protocol=vip["protocol"],
                ext_port=vip["extport"],
                mapped_port=vip["mappedport"],
                src_filter=vip["src_filter"],
                portmapping_type=vip["portmapping_type"],
                realservers=vip["realservers"],
            )
            db.add(new_vip)
        db.commit()

    print(
        "[bold green]VIP profile data updated successfully[/bold green] :white_check_mark:"
    )
    print("*" * 80)


def write_webfilter_info():
    """
    Get the web filter profile information from the clean_webfilter_data() function and
    write web filter profile information to the `webprofile` table in the database.
    """
    print(
        "[bold blue]Updating web filter profile data in database[/bold blue] :wrench:"
    )
    cleaned_data = clean_webfilter_data()

    with get_db() as db:
        db.query(WebProfile).delete()
        for profile in cleaned_data:
            hostname = profile["hostname"]
            device = db.query(Device).filter(Device.hostname == hostname).one()

            new_web_profile = WebProfile(
                device_id=device.device_id,
                name=profile["name"],
                comment=profile["comment"],
                options=profile["options"],
                https_replacemsg=profile["https_replacemsg"],
                override=profile["override"],
                web=profile["web"],
                ftgd_wf=profile["ftgd_wf"],
            )
            db.add(new_web_profile)
        db.commit()

    print(
        "[bold green]Web filter profile data updated successfully[/bold green] :white_check_mark:"
    )
    print("*" * 80)


def write_trafficshapers_info():
    """
    Get the traffic shapers information from the get_fortigate_trafficshapers_info() function and
    write traffic shapers information to the `trafficshapers` table in the database.
    """
    print("[bold blue]Updating traffic shapers data in database[/bold blue] :wrench:")
    cleaned_data = clean_trafficshapers_data()

    with get_db() as db:
        db.query(TrafficShaper).delete()
        for ts in cleaned_data:
            hostname = ts["hostname"]
            device = db.query(Device).filter(Device.hostname == hostname).one()
            traffic_shaper = TrafficShaper(
                device_id=device.device_id,
                name=ts["name"],
                guaranteed_bandwidth=ts["guaranteed_bandwidth"],
                maximum_bandwidth=ts["maximum_bandwidth"],
                bandwidth_unit=ts["bandwidth_unit"],
                priority=ts["priority"],
                per_policy=ts["per_policy"],
                diffserv=ts["diffserv"],
                diffservcode=ts["diffservcode"],
                dscp_marking_method=ts["dscp_marking_method"],
                exceed_bandwidth=ts["exceed_bandwidth"],
                exceed_dscp=ts["exceed_dscp"],
                maximum_dscp=ts["maximum_dscp"],
                overhead=ts["overhead"],
                exceed_class_id=ts["exceed_class_id"],
            )
            db.add(traffic_shaper)
        db.commit()

    print(
        "[bold green]Traffic shapers data updated successfully[/bold green] :white_check_mark:"
    )
    print("*" * 80)


def write_trafficpolicy_info():
    """
    Get the traffic shaper policy information from the clean_trafficpolicy_data() function and
    write traffic shaper policy information to the `trafficpolicy` table in the database.
    """
    print(
        "[bold blue]Updating traffic shaper policy data in database[/bold blue] :wrench:"
    )
    cleaned_data = clean_trafficpolicy_data()

    with get_db() as db:
        db.query(TrafficPolicy).delete()
        for policy in cleaned_data:
            hostname = policy["hostname"]
            device = db.query(Device).filter(Device.hostname == hostname).one()

            new_traffic_policy = TrafficPolicy(
                device_id=device.device_id,
                policy_id=policy["policy_id"],
                name=policy["name"],
                comment=policy["comment"],
                status=policy["status"],
                ip_version=policy["ip_version"],
                srcintf=policy["srcintf"],
                dstintf=policy["dstintf"],
                srcaddr=policy["srcaddr"],
                dstaddr=policy["dstaddr"],
                internet_service=policy["internet_service"],
                internet_service_name=policy["internet_service_name"],
                internet_service_group=policy["internet_service_group"],
                internet_service_custom=policy["internet_service_custom"],
                internet_service_src=policy["internet_service_src"],
                internet_service_src_name=policy["internet_service_src_name"],
                internet_service_src_group=policy["internet_service_src_group"],
                internet_service_src_custom=policy["internet_service_src_custom"],
                internet_service_src_custom_group=policy[
                    "internet_service_src_custom_group"
                ],
                service=policy["service"],
                schedule=policy["schedule"],
                users=policy["users"],
                groups=policy["groups"],
                application=policy["application"],
                app_group=policy["app_group"],
                url_category=policy["url_category"],
                traffic_shaper=policy["traffic_shaper"],
                traffic_shaper_reverse=policy["traffic_shaper_reverse"],
                per_ip_shaper=policy["per_ip_shaper"],
                class_id=policy["class_id"],
                diffserv_forward=policy["diffserv_forward"],
                diffserv_reverse=policy["diffserv_reverse"],
            )
            db.add(new_traffic_policy)
        db.commit()

    print(
        "[bold green]Traffic shaper policy data updated successfully[/bold green] :white_check_mark:"
    )
    print("*" * 80)


def write_fwpolicy_info():
    """
    Get the firewall policy information from the clean_fwpolicy_data() function and
    write firewall policy information to the `firewallpolicy` table in the database.
    """
    print("[bold blue]Updating firewallpolicy data in database[/bold blue] :wrench:")
    cleaned_data = clean_fwpolicy_data()

    with get_db() as db:
        db.query(FirewallPolicy).delete()
        for policy in cleaned_data:
            hostname = policy["hostname"]
            device = db.query(Device).filter(Device.hostname == hostname).one()

            new_fwpolicy = FirewallPolicy(
                device_id=device.device_id,
                policy_id=policy["policy_id"],
                fwpolicy_name=policy["fwpolicy_name"],
                fwpolicy_status=policy["fwpolicy_status"],
                srcintf=policy["srcintf"],
                dstintf=policy["dstintf"],
                action=policy["action"],
                nat64=policy["nat64"],
                nat46=policy["nat46"],
                srcaddr6=policy["srcaddr6"],
                dstaddr6=policy["dstaddr6"],
                srcaddr=policy["srcaddr"],
                dstaddr=policy["dstaddr"],
                internet_service_name=policy["internet-service-name"],
                internet_service_src_name=policy["internet-service-src-name"],
                internet_service_dynamic=policy["internet-service-dynamic"],
                internet_service_custom_group=policy["internet-service-custom-group"],
                internet_service=policy["internet-service"],
                internet_service_src=policy["internet-service-src"],
                internet_service_group=policy["internet-service-group"],
                internet_service_src_group=policy["internet-service-src-group"],
                internet_service_src_dynamic=policy["internet-service-src-dynamic"],
                internet_service_src_custom_group=policy[
                    "internet-service-src-custom-group"
                ],
                schedule=policy["schedule"],
                schedule_timeout=policy["schedule-timeout"],
                service=policy["service"],
                service_utm_status=policy["service-utm-status"],
                inspection_mode=policy["inspection-mode"],
                http_policy_redirect=policy["http-policy-redirect"],
                ssh_policy_redirect=policy["ssh-policy-redirect"],
                profile_type=policy["profile-type"],
                profile_group=policy["profile-group"],
                profile_protocol_options=policy["profile-protocol-options"],
                ssl_ssh_profile=policy["ssl-ssh-profile"],
                av_profile=policy["av-profile"],
                webfilter_profile=policy["webfilter-profile"],
                dnsfilter_profile=policy["dnsfilter-profile"],
                emailfilter_profile=policy["emailfilter-profile"],
                dlp_profile=policy["dlp-profile"],
                file_filter=policy["file-filter"],
                ips_sensor=policy["ips-sensor"],
                application_list=policy["application-list"],
                voip_profile=policy["voip-profile"],
                sctp_profile=policy["sctp-profile"],
                icap_profile=policy["icap-profile"],
                cifs_profile=policy["cifs-profile"],
                waf_profile=policy["waf-profile"],
                ssh_filter_profile=policy["ssh-filter-profile"],
                logtraffic=policy["logtraffic"],
                logtraffic_start=policy["logtraffic-start"],
                capture_packet=policy["capture-packet"],
                traffic_shaper=policy["traffic-shaper"],
                traffic_shaper_reverse=policy["traffic-shaper-reverse"],
                per_ip_shaper=policy["per-ip-shaper"],
                nat=policy["nat"],
                permit_any_host=policy["permit-any-host"],
                permit_stun_host=policy["permit-stun-host"],
                fixedport=policy["fixedport"],
                ippool=policy["ippool"],
                poolname=policy["poolname"],
                poolname6=policy["poolname6"],
                inbound=policy["inbound"],
                outbound=policy["outbound"],
                natinbound=policy["natinbound"],
                natoutbound=policy["natoutbound"],
                wccp=policy["wccp"],
                ntlm=policy["ntlm"],
                ntlm_guest=policy["ntlm-guest"],
                ntlm_enabled_browsers=policy["ntlm-enabled-browsers"],
                groups=policy["groups"],
                users=policy["users"],
                fsso_groups=policy["fsso-groups"],
                vpntunnel=policy["vpntunnel"],
                natip=policy["natip"],
                match_vip=policy["match-vip"],
                match_vip_only=policy["match-vip-only"],
                comments=policy["comments"],
                label=policy["label"],
                global_label=policy["global-label"],
                auth_cert=policy["auth-cert"],
                vlan_filter=policy["vlan-filter"],
            )
            db.add(new_fwpolicy)
        db.commit()

    print(
        "[bold green]Firewallpolicy data updated successfully[/bold green] :white_check_mark:"
    )
    print("*" * 80)


def write_vpn_monitor_info():
    """
    Get the VPN monitor information from the clean_vpn_monitor_data() function and
    write VPN monitor information to the `vpnmonitor` table in the database.
    """
    print("[bold blue]Updating VPN monitor in database[/bold blue] :wrench:")

    vpn_info = clean_vpn_monitor_data()

    with get_db() as db:
        db.query(VpnMonitor).delete()

        for vpn in vpn_info:
            hostname = vpn["hostname"]
            phase1_name = vpn["phase1_name"]
            phase2_names = vpn["phase2_name"]
            phase2_statuses = vpn["phase2_status"]

            device = db.query(Device).filter(Device.hostname == hostname).one()

            for i in range(len(phase2_names)):
                new_vpn_monitor = VpnMonitor(
                    device_id=device.device_id,
                    phase1_name=phase1_name,
                    phase2_name=phase2_names[i],
                    phase2_status=phase2_statuses[i],
                )

                db.add(new_vpn_monitor)

        db.commit()

    print(
        "[bold green]VPN monitor profile information updated successfully[/bold green] :white_check_mark:"
    )
    print("*" * 80)
