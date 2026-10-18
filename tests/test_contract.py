"""Every shipped backend passes the contract a third-party one runs."""

from dhcpctl.testing import BackendContract


class TestDnsmasq(BackendContract):
    uri = "dnsmasq:///?hostsfile=/srv/d/hosts/&optsfile=/srv/d/opts/&reload=true"
    secret_uri = "dnsmasq://admin:{secret}@dns01/?hostsfile=sftp://dns01/h/&reload=true"


class TestKea(BackendContract):
    uri = "kea://kea01/"
    secret_uri = "kea://admin:{secret}@kea01/"


class TestDhcpd(BackendContract):
    uri = "dhcpd://dhcp01/"
    secret_uri = "dhcpd://omapi_key:{secret}@dhcp01/"


class TestDhcpdGroups(BackendContract):
    uri = "dhcpd://dhcp01/?conditions=group"


class TestWindhcp(BackendContract):
    uri = "windhcp://dhcp01/?transport=winrm"
    secret_uri = "windhcp://admin:{secret}@dhcp01/?transport=winrm"


class TestWindhcpNetsh(BackendContract):
    uri = "windhcp://dhcp01/?transport=ssh&method=netsh"
