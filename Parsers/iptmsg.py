from __future__ import print_function

import re

pair_re = re.compile('([^ ]+)=([^ ]+)')
portlist = []
iplist = []


PORTMAP = {
     0:"DoS",        # Denial of Service
    1:"ICMP",        # ICMP
    20:"FTP",        # FTP Data
    21:"FTP",        # FTP Control
    22:"SSH",        # SSH
    23:"TELNET",     # Telnet
    25:"EMAIL",      # SMTP
    43:"WHOIS",      # Whois
    53:"DNS",        # DNS
    80:"HTTP",       # HTTP
    88:"AUTH",       # Kerberos
    109:"EMAIL",     # POP v2
    110:"EMAIL",     # POP v3
    115:"FTP",       # SFTP
    118:"SQL",       # SQL
    143:"EMAIL",     # IMAP
    156:"SQL",       # SQL
    161:"SNMP",      # SNMP
    220:"EMAIL",     # IMAP v3
    389:"AUTH",      # LDAP
    443:"HTTPS",     # HTTPS
    445:"SMB",       # SMB
    636:"AUTH",      # LDAP of SSL/TLS
    1433:"SQL",      # MySQL Server
    1434:"SQL",      # MySQL Monitor
    3306:"SQL",      # MySQL
    3389:"RDP",      # RDP
    5900:"RDP",      # VNC:0
    5901:"RDP",      # VNC:1
    5902:"RDP",      # VNC:2
    5903:"RDP",      # VNC:3
    8080:"HTTP",     # HTTP Alternative
}


def parse(line):
    """For now return the standard format for geoip-attack-map as csv:

        If <filter criteria matched>:
            SRC,DST,SPT,DPT,,
        else:
            None
    """

    # A quick & dirty trick to seperate the log body prefix from the tailing message part.
    hot = line.split('[allow-est-drop-i-default-D]')
    if len(hot) != 2:
        return None

    line = hot[1]

    line = line.rstrip()
    data = dict(pair_re.findall(line))

    try:
        portlist.append(data['DPT'])
        iplist.append(data['SRC'])
    except KeyError:
        pass

    # print(data)

    # A simple trick to filter traffic on our nic to the internet!
    if data['IN'] == 'eth5':
        dest_port = data.get('DPT', -1)
        return "{src},{dst},{spt},{dpt},{attack_type},{cve}".format(
            src=data.get('SRC', None),
            dst=data.get('DST', None),
            spt=data.get('SPT', -1),
            dpt=dest_port,
            attack_type=PORTMAP.get(int(dest_port), dest_port),
            cve='unknown')
    else:
        return None
