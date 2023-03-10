"""
This module contains all the sqlalchemy models/tables for the database.
"""

from sqlalchemy import (
    Column,
    Integer,
    Text,
    ForeignKey,
    UniqueConstraint,
    Text,
)
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()


class Device(Base):
    __tablename__ = "device"
    device_id = Column(Integer, primary_key=True)
    hostname = Column(Text)
    version = Column(Text)
    model = Column(Text)


class Interface(Base):
    __tablename__ = "interface"
    interface_id = Column(Integer, primary_key=True)
    name = Column(Text)
    vdom = Column(Text)
    mode = Column(Text)
    status = Column(Text)
    mtu = Column(Text)
    ip = Column(Text)
    type = Column(Text)
    allowaccess = Column(Text)
    device_id = Column(Integer, ForeignKey("device.device_id", ondelete="CASCADE"))
    __table_args__ = (UniqueConstraint("name", "device_id"),)
    device = relationship("Device", backref="interface")


class FirewallPolicy(Base):
    __tablename__ = "firewallpolicy"

    fwpolicy_id = Column(Integer, primary_key=True, autoincrement=True)
    policy_id = Column(Integer)
    fwpolicy_name = Column(Text)
    fwpolicy_status = Column(Text)
    srcintf = Column(Text)
    dstintf = Column(Text)
    action = Column(Text)
    nat64 = Column(Text)
    nat46 = Column(Text)
    srcaddr6 = Column(Text)
    dstaddr6 = Column(Text)
    srcaddr = Column(Text)
    dstaddr = Column(Text)
    internet_service_name = Column(Text)
    internet_service_src_name = Column(Text)
    internet_service_dynamic = Column(Text)
    internet_service_custom_group = Column(Text)
    internet_service = Column(Text)
    internet_service_src = Column(Text)
    internet_service_group = Column(Text)
    internet_service_src_group = Column(Text)
    internet_service_src_dynamic = Column(Text)
    internet_service_src_custom_group = Column(Text)
    schedule = Column(Text)
    schedule_timeout = Column(Text)
    service = Column(Text)
    service_utm_status = Column(Text)
    inspection_mode = Column(Text)
    http_policy_redirect = Column(Text)
    ssh_policy_redirect = Column(Text)
    profile_type = Column(Text)
    profile_group = Column(Text)
    profile_protocol_options = Column(Text)
    ssl_ssh_profile = Column(Text)
    av_profile = Column(Text)
    webfilter_profile = Column(Text)
    dnsfilter_profile = Column(Text)
    emailfilter_profile = Column(Text)
    dlp_profile = Column(Text)
    file_filter = Column(Text)
    ips_sensor = Column(Text)
    application_list = Column(Text)
    voip_profile = Column(Text)
    sctp_profile = Column(Text)
    icap_profile = Column(Text)
    cifs_profile = Column(Text)
    waf_profile = Column(Text)
    ssh_filter_profile = Column(Text)
    logtraffic = Column(Text)
    logtraffic_start = Column(Text)
    capture_packet = Column(Text)
    traffic_shaper = Column(Text)
    traffic_shaper_reverse = Column(Text)
    per_ip_shaper = Column(Text)
    nat = Column(Text)
    permit_any_host = Column(Text)
    permit_stun_host = Column(Text)
    fixedport = Column(Text)
    ippool = Column(Text)
    poolname = Column(Text)
    poolname6 = Column(Text)
    inbound = Column(Text)
    outbound = Column(Text)
    natinbound = Column(Text)
    natoutbound = Column(Text)
    wccp = Column(Text)
    ntlm = Column(Text)
    ntlm_guest = Column(Text)
    ntlm_enabled_browsers = Column(Text)
    groups = Column(Text)
    users = Column(Text)
    fsso_groups = Column(Text)
    vpntunnel = Column(Text)
    natip = Column(Text)
    match_vip = Column(Text)
    match_vip_only = Column(Text)
    comments = Column(Text)
    label = Column(Text)
    global_label = Column(Text)
    auth_cert = Column(Text)
    vlan_filter = Column(Text)
    device_id = Column(Integer, ForeignKey("device.device_id", ondelete="CASCADE"))
    device = relationship("Device")
    __table_args__ = (UniqueConstraint("fwpolicy_name", "device_id"),)


class WebProfile(Base):
    __tablename__ = "webprofile"

    webprofile_id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(Text)
    comment = Column(Text)
    options = Column(Text)
    https_replacemsg = Column(Text)
    override = Column(Text)
    web = Column(Text)
    ftgd_wf = Column(Text)
    device_id = Column(Integer, ForeignKey("device.device_id", ondelete="CASCADE"))
    device = relationship("Device")
    __table_args__ = (UniqueConstraint("name", "device_id"),)


class DnsProfile(Base):
    __tablename__ = "dnsprofile"

    dnsprofile_id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(Text)
    comment = Column(Text)
    domain_filter = Column(Text)
    ftgd_dns = Column(Text)
    block_botnet = Column(Text)
    safe_search = Column(Text)
    youtube_restrict = Column(Text)
    device_id = Column(Integer, ForeignKey("device.device_id", ondelete="CASCADE"))
    device = relationship("Device")
    __table_args__ = (UniqueConstraint("name", "device_id"),)


class AppProfile(Base):
    __tablename__ = "appprofile"

    appprofile_id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(Text)
    comment = Column(Text)
    entries = Column(Text)
    device_id = Column(Integer, ForeignKey("device.device_id", ondelete="CASCADE"))
    device = relationship("Device")
    __table_args__ = (UniqueConstraint("name", "device_id"),)


class IpsProfile(Base):
    __tablename__ = "ipsprofile"

    ipsprofile_id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(Text)
    comment = Column(Text)
    block_malicious_url = Column(Text)
    scan_botnet_connections = Column(Text)
    extended_log = Column(Text)
    entries = Column(Text)
    device_id = Column(Integer, ForeignKey("device.device_id", ondelete="CASCADE"))
    device = relationship("Device")
    __table_args__ = (UniqueConstraint("name", "device_id"),)


class SslSshProfile(Base):
    __tablename__ = "sslsshprofile"

    allowlist = Column(Text)
    block_blocklisted_certificates = Column(Text)
    caname = Column(Text)
    comment = Column(Text)
    device_id = Column(Integer, ForeignKey("device.device_id", ondelete="CASCADE"))
    dot = Column(Text)
    ftps = Column(Text)
    https = Column(Text)
    imaps = Column(Text)
    mapi_over_https = Column(Text)
    name = Column(Text)
    pop3s = Column(Text)
    rpc_over_https = Column(Text)
    smtps = Column(Text)
    ssl = Column(Text)
    ssl_exempt = Column(Text)
    ssl_exemption_ip_rating = Column(Text)
    ssl_server = Column(Text)
    ssh = Column(Text)
    untrusted_caname = Column(Text)
    sslsshprofile_id = Column(Integer, primary_key=True, autoincrement=True)
    device = relationship("Device")
    __table_args__ = (UniqueConstraint("name", "device_id"),)


class AvProfile(Base):
    __tablename__ = "avprofile"

    avprofile_id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(Text)
    comment = Column(Text)
    http = Column(Text)
    ftp = Column(Text)
    imap = Column(Text)
    pop3 = Column(Text)
    smtp = Column(Text)
    mapi = Column(Text)
    nntp = Column(Text)
    cifs = Column(Text)
    ssh = Column(Text)
    nac_quar = Column(Text)
    content_disarm = Column(Text)
    device_id = Column(Integer, ForeignKey("device.device_id", ondelete="CASCADE"))
    device = relationship("Device")
    __table_args__ = (UniqueConstraint("name", "device_id"),)


class Address(Base):
    __tablename__ = "address"

    address_id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(Text)
    subnet = Column(Text)
    address_type = Column(Text)
    start_ip = Column(Text)
    end_ip = Column(Text)
    fqdn = Column(Text)
    country = Column(Text)
    associated_interface = Column(Text)
    device_id = Column(Integer, ForeignKey("device.device_id", ondelete="CASCADE"))
    device = relationship("Device")
    __table_args__ = (UniqueConstraint("name", "device_id"),)


class AddressGroup(Base):
    __tablename__ = "addressgroup"

    address_group_id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(Text)
    member = Column(Text)
    device_id = Column(Integer, ForeignKey("device.device_id", ondelete="CASCADE"))
    device = relationship("Device")
    __table_args__ = (UniqueConstraint("name", "device_id"),)


class InternetService(Base):
    __tablename__ = "internetservice"

    internet_service_id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(Text)
    type = Column(Text)
    device_id = Column(Integer, ForeignKey("device.device_id", ondelete="CASCADE"))
    device = relationship("Device")
    __table_args__ = (UniqueConstraint("name", "device_id"),)


class IpPool(Base):
    __tablename__ = "ippool"

    ippool_id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(Text)
    type = Column(Text)
    start_ip = Column(Text)
    end_ip = Column(Text)
    startport = Column(Text)
    endport = Column(Text)
    source_start_ip = Column(Text)
    source_end_ip = Column(Text)
    arp_reply = Column(Text)
    arp_intf = Column(Text)
    associated_interface = Column(Text)
    comments = Column(Text)
    device_id = Column(Integer, ForeignKey("device.device_id", ondelete="CASCADE"))
    device = relationship("Device")
    __table_args__ = (UniqueConstraint("name", "device_id"),)


class Vip(Base):
    __tablename__ = "vip"

    vip_id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(Text)
    comment = Column(Text)
    type = Column(Text)
    ext_ip = Column(Text)
    ext_addr = Column(Text)
    nat44 = Column(Text)
    mapped_ip = Column(Text)
    mapped_addr = Column(Text)
    ext_intf = Column(Text)
    arp_reply = Column(Text)
    portforward = Column(Text)
    status = Column(Text)
    protocol = Column(Text)
    ext_port = Column(Text)
    mapped_port = Column(Text)
    src_filter = Column(Text)
    portmapping_type = Column(Text)
    realservers = Column(Text)
    interface_id = Column(Integer, ForeignKey("interface.interface_id"))
    interface = relationship("Interface")
    device_id = Column(Integer, ForeignKey("device.device_id", ondelete="CASCADE"))
    device = relationship("Device")
    __table_args__ = (UniqueConstraint("name", "device_id"),)


class TrafficShaper(Base):
    __tablename__ = "trafficshapers"

    trafficshaper_id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(Text)
    guaranteed_bandwidth = Column(Text)
    maximum_bandwidth = Column(Text)
    bandwidth_unit = Column(Text)
    priority = Column(Text)
    per_policy = Column(Text)
    diffserv = Column(Text)
    diffservcode = Column(Text)
    dscp_marking_method = Column(Text)
    exceed_bandwidth = Column(Text)
    exceed_dscp = Column(Text)
    maximum_dscp = Column(Text)
    overhead = Column(Text)
    exceed_class_id = Column(Text)
    device_id = Column(Integer, ForeignKey("device.device_id", ondelete="CASCADE"))
    device = relationship("Device")


class TrafficPolicy(Base):
    __tablename__ = "trafficpolicy"

    trafficpolicy_id = Column(Integer, primary_key=True, autoincrement=True)
    policy_id = Column(Text)
    name = Column(Text)
    comment = Column(Text)
    status = Column(Text)
    ip_version = Column(Text)
    srcintf = Column(Text)
    dstintf = Column(Text)
    srcaddr = Column(Text)
    dstaddr = Column(Text)
    internet_service = Column(Text)
    internet_service_name = Column(Text)
    internet_service_group = Column(Text)
    internet_service_custom = Column(Text)
    internet_service_src = Column(Text)
    internet_service_src_name = Column(Text)
    internet_service_src_group = Column(Text)
    internet_service_src_custom = Column(Text)
    internet_service_src_custom_group = Column(Text)
    service = Column(Text)
    schedule = Column(Text)
    users = Column(Text)
    groups = Column(Text)
    application = Column(Text)
    app_group = Column(Text)
    url_category = Column(Text)
    traffic_shaper = Column(Text)
    traffic_shaper_reverse = Column(Text)
    per_ip_shaper = Column(Text)
    class_id = Column(Text)
    diffserv_forward = Column(Text)
    diffserv_reverse = Column(Text)
    device_id = Column(Integer, ForeignKey("device.device_id", ondelete="CASCADE"))
    device = relationship("Device")


class DNS(Base):
    __tablename__ = "dns"
    dns_id = Column(Integer, primary_key=True)
    primary_dns = Column(Text)
    secondary_dns = Column(Text)
    protocol = Column(Text)
    ssl_certificate = Column(Text)
    server_hostname = Column(Text)
    domain = Column(Text)
    ip6_primary = Column(Text)
    ip6_secondary = Column(Text)
    dns_timeout = Column(Text)
    retry = Column(Text)
    cache_limit = Column(Text)
    cache_ttl = Column(Text)
    source_ip = Column(Text)
    interface_select_method = Column(Text)
    interface = Column(Text)
    server_select_method = Column(Text)
    alt_primary = Column(Text)
    alt_secondary = Column(Text)
    log_fqdn = Column(Text)
    device_id = Column(Integer, ForeignKey("device.device_id", ondelete="CASCADE"))
    device = relationship("Device")


class StaticRoute(Base):
    __tablename__ = "staticroute"
    static_route_id = Column(Integer, primary_key=True)
    seq_num = Column(Text)
    status = Column(Text)
    dst = Column(Text)
    src = Column(Text)
    gateway = Column(Text)
    distance = Column(Text)
    weight = Column(Text)
    priority = Column(Text)
    interface = Column(Text)
    comment = Column(Text)
    blackhole = Column(Text)
    dynamic_gateway = Column(Text)
    sdwan_zone = Column(Text)
    dstaddr = Column(Text)
    internet_service = Column(Text)
    internet_service_custom = Column(Text)
    tag = Column(Text)
    vrf = Column(Text)
    bfd = Column(Text)
    device_id = Column(Integer, ForeignKey("device.device_id", ondelete="CASCADE"))
    device = relationship("Device")


class PolicyRoute(Base):
    __tablename__ = "policyroute"
    policy_route_id = Column(Integer, primary_key=True)
    seq_num = Column(Integer)
    input_device = Column(Text)
    input_device_negate = Column(Text)
    src = Column(Text)
    srcaddr = Column(Text)
    src_negate = Column(Text)
    dst = Column(Text)
    dstaddr = Column(Text)
    dst_negate = Column(Text)
    action = Column(Text)
    protocol = Column(Text)
    start_port = Column(Text)
    end_port = Column(Text)
    start_source_port = Column(Text)
    end_source_port = Column(Text)
    gateway = Column(Text)
    output_device = Column(Text)
    status = Column(Text)
    comments = Column(Text)
    internet_service_id = Column(Text)
    internet_service_custom = Column(Text)
    device_id = Column(Integer, ForeignKey("device.device_id", ondelete="CASCADE"))
    device = relationship("Device")


class SnmpV2(Base):
    __tablename__ = "snmpv2"
    snmpv2_id = Column(Integer, primary_key=True)
    id = Column(Integer)
    name = Column(Text)
    status = Column(Text)
    host = Column(Text)
    host6 = Column(Text)
    query_v1_status = Column(Text)
    query_v1_port = Column(Text)
    query_v2c_status = Column(Text)
    query_v2c_port = Column(Text)
    query_trap_v1_status = Column(Text)
    query_trap_v1_rport = Column(Text)
    query_trap_v2c_status = Column(Text)
    query_trap_v2c_lport = Column(Text)
    query_trap_v2c_rport = Column(Text)
    events = Column(Text)
    vdoms = Column(Text)
    device_id = Column(Integer, ForeignKey("device.device_id", ondelete="CASCADE"))
    device = relationship("Device")


class Snmpv3(Base):
    __tablename__ = "snmpv3"

    snmpv3_id = Column(Integer, primary_key=True)
    name = Column(Text)
    status = Column(Text)
    trap_status = Column(Text)
    trap_lport = Column(Integer)
    trap_rport = Column(Integer)
    queries = Column(Text)
    query_port = Column(Integer)
    notify_hosts = Column(Text)
    notify_hosts6 = Column(Text)
    source_ip = Column(Text)
    source_ipv6 = Column(Text)
    events = Column(Text)
    vdoms = Column(Text)
    security_level = Column(Text)
    auth_proto = Column(Text)
    priv_proto = Column(Text)
    priv_pwd = Column(Text)
    device_id = Column(Integer, ForeignKey("device.device_id", ondelete="CASCADE"))
    device = relationship("Device")


class FortiGuard(Base):
    __tablename__ = "fortiguard"

    fortiguard_id = Column(Integer, primary_key=True)
    fortiguard_anycast = Column(Text)
    fortiguard_anycast_source = Column(Text)
    protocol = Column(Text)
    port = Column(Text)
    service_account_id = Column(Text)
    load_balace_servers = Column(Text)
    auto_join_forticloud = Column(Text)
    update_server_location = Column(Text)
    sandbox_region = Column(Text)
    sandbox_inline_scan = Column(Text)
    update_ffdb = Column(Text)
    update_uwdb = Column(Text)
    update_extdb = Column(Text)
    update_build_proxy = Column(Text)
    persistent_connection = Column(Text)
    vdom = Column(Text)
    auto_firmware_upgrade = Column(Text)
    auto_firmware_upgrade_day = Column(Text)
    auto_firmware_upgrade_start_hour = Column(Text)
    auto_firmware_upgrade_end_hour = Column(Text)
    antispam_force_off = Column(Text)
    antispam_cache = Column(Text)
    antispam_cache_ttl = Column(Text)
    antispam_cache_mpercent = Column(Text)
    antispam_license = Column(Text)
    antispam_expiration = Column(Text)
    antispam_timeout = Column(Text)
    outbreak_prevention_force_off = Column(Text)
    outbreak_prevention_cache = Column(Text)
    outbreak_prevention_cache_ttl = Column(Text)
    outbreak_prevention_cache_mpercent = Column(Text)
    outbreak_prevention_license = Column(Text)
    outbreak_prevention_expiration = Column(Text)
    outbreak_prevention_timeout = Column(Text)
    webfilter_force_off = Column(Text)
    webfilter_cache = Column(Text)
    webfilter_cache_ttl = Column(Text)
    webfilter_license = Column(Text)
    webfilter_expiration = Column(Text)
    webfilter_timeout = Column(Text)
    sdns_server_ip = Column(Text)
    sdns_server_port = Column(Text)
    anycast_sdns_server_ip = Column(Text)
    anycast_sdns_server_port = Column(Text)
    sdns_options = Column(Text)
    source_ip = Column(Text)
    source_ip6 = Column(Text)
    proxy_server_ip = Column(Text)
    proxy_server_port = Column(Text)
    proxy_username = Column(Text)
    proxy_password = Column(Text)
    ddns_server_ip = Column(Text)
    ddns_server_ip6 = Column(Text)
    ddns_server_port = Column(Text)
    interface_select_method = Column(Text)
    interface = Column(Text)
    device_id = Column(Integer, ForeignKey("device.device_id", ondelete="CASCADE"))
    device = relationship("Device")


class Admin(Base):
    __tablename__ = "admin"

    admin_id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(Text)
    wildcard = Column(Text)
    remote_auth = Column(Text)
    remote_group = Column(Text)
    trusthost1 = Column(Text)
    trusthost2 = Column(Text)
    trusthost3 = Column(Text)
    trusthost4 = Column(Text)
    trusthost5 = Column(Text)
    trusthost6 = Column(Text)
    trusthost7 = Column(Text)
    trusthost8 = Column(Text)
    trusthost9 = Column(Text)
    trusthost10 = Column(Text)
    ip6_trusthost1 = Column(Text)
    ip6_trusthost2 = Column(Text)
    ip6_trusthost3 = Column(Text)
    ip6_trusthost4 = Column(Text)
    ip6_trusthost5 = Column(Text)
    ip6_trusthost6 = Column(Text)
    ip6_trusthost7 = Column(Text)
    ip6_trusthost8 = Column(Text)
    ip6_trusthost9 = Column(Text)
    ip6_trusthost10 = Column(Text)
    accprofile = Column(Text)
    allow_remove_admin_session = Column(Text)
    comments = Column(Text)
    vdoms = Column(Text)
    force_password_change = Column(Text)
    two_factor = Column(Text)
    two_factor_authentication = Column(Text)
    two_factor_notification = Column(Text)
    device_id = Column(Integer, ForeignKey("device.device_id", ondelete="CASCADE"))
    device = relationship("Device")


class AdminProfile(Base):
    __tablename__ = "adminprofile"

    adminprofile_id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(Text)
    scope = Column(Text)
    comments = Column(Text)
    ftviewgrp = Column(Text)
    authgrp = Column(Text)
    sysgrp = Column(Text)
    netgrp = Column(Text)
    loggrp = Column(Text)
    fwgrp = Column(Text)
    vpngrp = Column(Text)
    utmgrp = Column(Text)
    wanoptgrp = Column(Text)
    wifi = Column(Text)
    netgrp_permission = Column(Text)
    sysgrp_permission = Column(Text)
    fwgrp_permission = Column(Text)
    loggrp_permission = Column(Text)
    utmgrp_permission = Column(Text)
    admintimeout_override = Column(Text)
    admintimeout = Column(Text)
    systemdiagnostics = Column(Text)
    system_execute_ssh = Column(Text)
    system_execute_telnet = Column(Text)
    device_id = Column(Integer, ForeignKey("device.device_id", ondelete="CASCADE"))
    device = relationship("Device")


class VpnMonitor(Base):
    __tablename__ = "vpnmonitor"

    vpnmonitor_id = Column(Integer, primary_key=True)
    phase1_name = Column(Text, nullable=False)
    phase2_name = Column(Text, nullable=False)
    phase2_status = Column(Text, nullable=False)
    device_id = Column(Integer, ForeignKey("device.device_id", ondelete="CASCADE"))
    device = relationship("Device")
