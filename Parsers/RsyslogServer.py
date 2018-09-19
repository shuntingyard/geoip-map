from __future__ import print_function

import argparse
import json

try:
    import SocketServer
except ModuleNotFoundError:
    import socketserver as SocketServer

import sys

import iptmsg

from threading import Thread

from syslogmp import parse
# from syslog_rfc5424_parser import SyslogMessage, ParseError


PORT = 514
HOST = ""


def parse_n_print(message): 
    # Technically, messages are only UTF-8 if they have a BOM; otherwise they're binary. However, I'm not
    # aware of any Syslog servers that handle that. *shrug*

    # message = message.decode('utf-8')
    # try:
    #     message = SyslogMessage.parse(message)
    #     print(json.dumps(message.as_dict()))
    # except ParseError as e:
    #     print(e, file=sys.stderr)
    #     print(8*'----+----|')
    #     print(message)

    parsed = parse(message)
    # print(parsed.timestamp)
    body = parsed.message.decode('utf-8')
    # print(body)

    csv = iptmsg.parse(body)
    if csv is not None:
        print("{} {} {}: {}".format(
            parsed.timestamp,
            parsed.hostname,
            sys.argv[0],
            csv))


class MySocketServerHandler(SocketServer.BaseRequestHandler):
 
    def handle(self):
        parse_n_print(self.request[0].strip())
     

def start_udp():
    print("Starting UDP Server at port %s " % PORT, file=sys.stderr)
    server_s = SocketServer.UDPServer((HOST, PORT), MySocketServerHandler)
    server_s.serve_forever()
 
 
def start_tcp():
    print("Starting TCP Server at port %s " % PORT, file=sys.stderr)
    server_s = SocketServer.TCPServer((HOST, PORT), MySocketServerHandler)
    server_s.serve_forever()
 
 
if __name__ == "__main__":
    print("Starting server...", file=sys.stderr)
 
    parser = argparse.ArgumentParser(description='Bugtower rsyslog server')
    parser.add_argument('--tcp', help='Start TCP server', action='store_true', default=False, required=False)
    parser.add_argument('--udp', help='Start UDP server', action='store_true', default=False, required=False)
    parser.add_argument('--port', help='Port for servers', default=514, required=False)
    args = parser.parse_args()
 
    PORT = int(args.port)
 
    if args.udp:
        # t = Thread(target=start_udp)
        # t.start()
        start_udp()
    if args.tcp:
        t2 = Thread(target=start_tcp)
        t2.start()
