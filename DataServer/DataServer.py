"""
AUTHORS:    Matthew May - mcmay.web@gmail.com
            Tobias Frei - shuntingyard@gmail.com
"""

import logging
import socketserver
import struct
import urllib.request

from ipaddress import ip_address
from datetime import datetime

import maxminddb

from const import META, PORTMAP


# globals
logger = logging.getLogger(__name__)
mmreader = None  # for maxminddb

# Used to replace private IP addresses in flows. TODO Make this configurable.
hq_ipa = urllib.request.urlopen('https://ident.me').read().decode('utf8')
hq_lat = None
hq_long = None  # latter two initialized from main

HEADER_LEN = 24  # these are for NetFlow V5 wire level
DATA_LEN = 48


# strip unwanted attributes from maxmind lookup results
def geo_lookup(ip_str):
    info = mmreader.get(ip_str)
    if not info:
        raise KeyError(ip_str)

    def clean_db(unclean):
        selected = {}
        for tag in META:
            head = None
            if tag["tag"] in unclean:
                head = unclean[tag["tag"]]
                for node in tag["path"]:
                    if node in head:
                        head = head[node]
                    else:
                        head = None
                        break
                selected[tag["lookup"]] = head

        return selected
    return clean_db(info)


def append_geoinfo(flow):
    """TODO"""

    if flow["src_ip"].is_private:

        flow["src_ip"] = hq_ipa
        flow["src_lat"] = hq_lat
        flow["src_long"] = hq_long

        addr = str(flow["dst_ip"])
        flow.update(geo_lookup(addr))
        flow["dst_ip"] = addr
    else:
        flow["dst_ip"] = hq_ipa
        flow["dst_lat"] = hq_lat
        flow["dst_long"] = hq_long

        addr = str(flow["src_ip"])
        flow.update(geo_lookup(addr))
        flow["src_ip"] = addr

    # rewrite flow attributes
    flow["src_port"] = PORTMAP.get(flow["src_port"], flow["src_port"])
    flow["dst_port"] = PORTMAP.get(flow["dst_port"], flow["dst_port"])

    print(flow)


def filter(unpacked):
    """Return True if ip addresses accepted"""
    private = False
    for ipn in unpacked[:2]:
        ipa = ip_address(ipn)
        if ipa.is_link_local or ipa.is_multicast:
            return False
        if private and ipa.is_private:
            return False  # intranet only
        if ipa.is_private:
            private = True
    return True


def process_nf5(export_t, count, packet):
    """Unpack netflow data (and pass on to put JSON msg together)"""

    for i in range(count):
        ptr = HEADER_LEN + i * DATA_LEN

        # quick again, we just unpack the data we want to pass on
        unpacked = struct.unpack(
            "!II" + 24 * "x" + "HHxxB" + 9 * "x", packet[ptr : ptr + DATA_LEN]
        )

        # drop broadcast, multicast etc.
        if not filter(unpacked):
            continue

        flow = {}
        flow["src_ip"] = ip_address(unpacked[0])
        flow["dst_ip"] = ip_address(unpacked[1])
        flow["src_port"] = unpacked[2]
        flow["dst_port"] = unpacked[3]
        flow["protocol"] = unpacked[4]

        # Not strictly from Cisco, but good for the app server
        flow["type"] = "LogXY"

        # TODO For now the export time is taken. But this is inaccurate as
        # flows for long TPC connections do have started earlier.
        flow["event_time"] = datetime.fromtimestamp(export_t).strftime(
            "%b %m %Y %H:%M:%S"
        )

        append_geoinfo(flow)


class SocketServerHandler(socketserver.BaseRequestHandler):
    def handle(self):
        """Basics to handle wire-level NetFlow"""
        addr = self.client_address[0]

        export_packet = self.request[0]

        # make it quick, take version, count, time and engine_id
        header = struct.unpack(
            "!HHxxxxIxxxxxxxxxBxx", export_packet[:HEADER_LEN]
        )
        ver, count, export_t, engine_id = header

        if ver != 5:
            logger.error("Bad packet, I want NetFlow V5!")
        else:
            logger.debug(
                "Got {:4d} bytes from exporter {:d} at {}".format(
                    len(export_packet), engine_id, addr
                )
            )

        # quick test: total packet length must be:
        total = HEADER_LEN + count * DATA_LEN
        assert total == len(export_packet)

        process_nf5(export_t, count, export_packet)


def main():
    """For module testing"""

    # stuff to be configurable

    db_path = "../DataServerDB/GeoLite2-City.mmdb"
    host = "0.0.0.0"
    port = 2055

    # the minimum to see what we're doing
    logging.basicConfig(level=logging.DEBUG)

    # load
    logging.info("Loading maxminddb...")
    global mmreader
    mmreader = maxminddb.open_database(db_path)

    # init headquarters
    global hq_lat, hq_long
    geo = geo_lookup(hq_ipa)
    hq_lat = geo["latitude"]
    hq_long = geo["longitude"]

    s = socketserver.UDPServer((host, port), SocketServerHandler)
    logging.info("UDP listener on %s:%d" % (s.server_address[0], port))
    try:
        s.serve_forever()
    except KeyboardInterrupt:
        s.shutdown()
        logging.info("listener shutdown")


if __name__ == "__main__":
    main()
