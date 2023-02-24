CREATE TABLE device (
  device_id INTEGER PRIMARY KEY AUTOINCREMENT,
  hostname TEXT,
  serial_number TEXT,
  version TEXT,
  model TEXT
);

CREATE TABLE interface (
  interface_id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT,
  vdom TEXT,
  mode TEXT,
  status TEXT,
  mtu INTEGER,
  ip TEXT,
  type TEXT,
  allowaccess TEXT,
  device_id INTEGER,
  FOREIGN KEY (device_id) REFERENCES device(device_id)
  UNIQUE (name, device_id)
);

CREATE TABLE firewallpolicy (
  fwpolicy_id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT,
  comment TEXT,
  srcintf TEXT,
  dstintf TEXT,
  action TEXT,
  src_addr TEXT,
  src_addrgroup TEXT,
  src_user TEXT,
  src_vip TEXT,
  src_internetservice_name TEXT,
  src_internetservice_enable TEXT,
  dst_internetservice_enable TEXT,
  dst_internetservice_name TEXT,
  src_usergroup TEXT,
  dst_addr TEXT,
  dst_group TEXT,
  dst_vip TEXT,
  schedule TEXT,
  service TEXT,
  utm_status TEXT,
  nat TEXT,
  ippool TEXT,
  poolname TEXT,
  interface_id INTEGER,
  sslsshprofile_id INTEGER,
  avprofile_id INTEGER,
  webprofile_id INTEGER,
  dnsprofile_id INTEGER,
  ipsprofile_id INTEGER,
  appprofile_id INTEGER,
  address_group_id INTEGER,
  address_id INTEGER,
  internet_service_id INTEGER,
  ippool_id INTEGER,
  vip_id INTEGER,
  device_id INTEGER,
  FOREIGN KEY (interface_id) REFERENCES interface(interface_id),
  FOREIGN KEY (device_id) REFERENCES device(device_id),
  FOREIGN KEY (sslsshprofile_id) REFERENCES sslsshprofile(sslsshprofile_id),
  FOREIGN KEY (avprofile_id) REFERENCES avprofile(avprofile_id),
  FOREIGN KEY (webprofile_id) REFERENCES webprofile(webprofile_id),
  FOREIGN KEY (dnsprofile_id) REFERENCES dnsprofile(dnsprofile_id),
  FOREIGN KEY (ipsprofile_id) REFERENCES ipsprofile(ipsprofile_id),
  FOREIGN KEY (appprofile_id) REFERENCES appprofile(appprofile_id),
  FOREIGN KEY (address_group_id) REFERENCES addressgroup(address_group_id),
  FOREIGN KEY (address_id) REFERENCES address(address_id),
  FOREIGN KEY (internet_service_id) REFERENCES internetservice(internet_service_id),
  FOREIGN KEY (ippool_id) REFERENCES ippool(ippool_id),
  FOREIGN KEY (vip_id) REFERENCES vip(vip_id)
  UNIQUE (name, device_id)
);

CREATE TABLE webprofile (
  webprofile_id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT,
  comment TEXT,
  options TEXT,
  "web ftgd-wf" TEXT,
  device_id INTEGER,
  FOREIGN KEY (device_id) REFERENCES device(device_id)
  UNIQUE (name, device_id)
);

CREATE TABLE dnsprofile (
  dnsprofile_id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT,
  comment TEXT,
  domain_filter TEXT,
  ftgd_dns TEXT,
  block_botnet TEXT,
  safe_search TEXT,
  youtube_restrict TEXT,
  device_id INTEGER,
  FOREIGN KEY (device_id) REFERENCES device(device_id)
  UNIQUE (name, device_id)
);

CREATE TABLE appprofile (
  appprofile_id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT,
  comment TEXT,
  entries TEXT,
  device_id INTEGER,
  FOREIGN KEY (device_id) REFERENCES device(device_id)
  UNIQUE (name, device_id)
);

CREATE TABLE ipsprofile (
  ipsprofile_id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT,
  comment TEXT,
  block_malicious_url TEXT,
  scan_botnet_connections TEXT,
  extended_log TEXT,
  entries TEXT,
  device_id INTEGER,
  FOREIGN KEY (device_id) REFERENCES device(device_id)
  UNIQUE (name, device_id)
);

CREATE TABLE sslsshprofile (
allowlist TEXT,
block_blocklisted_certificates TEXT,
caname TEXT,
comment TEXT,
device_id INTEGER,
dot TEXT,
ftps TEXT,
https TEXT,
imaps TEXT,
mapi_over_https TEXT,
name TEXT,
pop3s TEXT,
rpc_over_https TEXT,
smtps TEXT,
ssl TEXT,
ssl_exempt TEXT,
ssl_exemption_ip_rating TEXT,
ssl_server TEXT,
ssh TEXT,
untrusted_caname TEXT,
sslsshprofile_id INTEGER PRIMARY KEY AUTOINCREMENT,
FOREIGN KEY (device_id) REFERENCES device(device_id)
UNIQUE (name, device_id)
);

CREATE TABLE avprofile (
avprofile_id INTEGER PRIMARY KEY AUTOINCREMENT,
name TEXT,
comment TEXT,
http TEXT,
ftp TEXT,
imap TEXT,
pop3 TEXT,
smtp TEXT,
mapi TEXT,
nntp TEXT,
cifs TEXT,
ssh TEXT,
nac_quar TEXT,
content_disarm TEXT,
device_id INTEGER,
FOREIGN KEY (device_id) REFERENCES device(device_id),
UNIQUE (name, device_id)
);

CREATE TABLE address (
address_id INTEGER PRIMARY KEY AUTOINCREMENT,
name TEXT,
subnet TEXT,
address_type TEXT,
start_ip TEXT,
end_ip TEXT,
fqdn TEXT,
country TEXT,
associated_interface TEXT,
device_id INTEGER,
FOREIGN KEY (device_id) REFERENCES device(device_id),
UNIQUE (name, device_id)
);

CREATE TABLE addressgroup (
address_group_id INTEGER PRIMARY KEY AUTOINCREMENT,
name TEXT,
member TEXT,
device_id INTEGER,
FOREIGN KEY (device_id) REFERENCES device(device_id)
UNIQUE (name, device_id)
);

CREATE TABLE address_group_member (
address_group_member_id INTEGER PRIMARY KEY AUTOINCREMENT,
address_group_id INTEGER,
address_id INTEGER,
device_id INTEGER,
FOREIGN KEY (address_group_id) REFERENCES addressgroup(address_group_id),
FOREIGN KEY (address_id) REFERENCES address(address_id),
FOREIGN KEY (device_id) REFERENCES device(device_id)
);

CREATE TABLE internetservice (
internet_service_id INTEGER PRIMARY KEY AUTOINCREMENT,
name TEXT,
type TEXT,
device_id INTEGER,
FOREIGN KEY (device_id) REFERENCES device(device_id)
UNIQUE (name, device_id)
);

CREATE TABLE ippool (
ippool_id INTEGER PRIMARY KEY AUTOINCREMENT,
name TEXT,
type TEXT,
start_ip TEXT,
end_ip TEXT,
startport TEXT,
endport TEXT,
source_start_ip TEXT,
source_end_ip TEXT,
arp_reply TEXT,
arp_intf TEXT,
associated_interface TEXT,
comments TEXT,
device_id INTEGER,
FOREIGN KEY (device_id) REFERENCES device(device_id)
UNIQUE (name, device_id)
);

CREATE TABLE vip (
vip_id INTEGER PRIMARY KEY AUTOINCREMENT,
name TEXT,
comment TEXT,
type TEXT,
ext_ip TEXT,
ext_addr TEXT,
nat44 TEXT,
mapped_ip TEXT,
mapped_addr TEXT,
ext_intf TEXT,
arp_reply TEXT,
portforward TEXT,
status TEXT,
protocol TEXT,
ext_port TEXT,
mapped_port TEXT,
src_filter TEXT,
portmapping_type TEXT,
realservers TEXT,
interface_id INTEGER,
device_id INTEGER,
FOREIGN KEY (interface_id) REFERENCES interface(interface_id),
FOREIGN KEY (device_id) REFERENCES device(device_id)
UNIQUE (name, device_id)
);
