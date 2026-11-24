#!/usr/bin/env python3
"""A minimal UPnP Internet Gateway Device, for testing the host's automatic
port forwarding without a real router.

Usage: fake_router.py SSDP_PORT HTTP_PORT EXTERNAL_IP LOG_FILE

Answers SSDP discovery on 127.0.0.1:SSDP_PORT and serves the device
description and the WANIPConnection SOAP actions on HTTP_PORT. Every SOAP
action is appended to LOG_FILE as `Action key=value ...`.
Point the host at it with HYPERSPACE_UPNP_SEARCH=127.0.0.1:SSDP_PORT.
"""
import re
import socket
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

ssdp_port, http_port, external_ip, log_path = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3], sys.argv[4]
SERVICE = "urn:schemas-upnp-org:service:WANIPConnection:1"

DESC = f"""<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
 <specVersion><major>1</major><minor>0</minor></specVersion>
 <device>
  <deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
  <friendlyName>Fake router</friendlyName>
  <deviceList><device>
   <deviceType>urn:schemas-upnp-org:device:WANDevice:1</deviceType>
   <deviceList><device>
    <deviceType>urn:schemas-upnp-org:device:WANConnectionDevice:1</deviceType>
    <serviceList><service>
     <serviceType>{SERVICE}</serviceType>
     <serviceId>urn:upnp-org:serviceId:WANIPConn1</serviceId>
     <controlURL>/ctl</controlURL>
     <eventSubURL>/evt</eventSubURL>
     <SCPDURL>/scpd.xml</SCPDURL>
    </service></serviceList>
   </device></deviceList>
  </device></deviceList>
 </device>
</root>"""


def action(name, args):
    items = "".join(f"<argument><name>{a}</name><direction>{d}</direction></argument>" for a, d in args)
    return f"<action><name>{name}</name><argumentList>{items}</argumentList></action>"


MAPPING_ARGS = [(n, "in") for n in ("NewRemoteHost", "NewExternalPort", "NewProtocol", "NewInternalPort",
                                    "NewInternalClient", "NewEnabled", "NewPortMappingDescription", "NewLeaseDuration")]
SCPD = ('<?xml version="1.0"?><scpd xmlns="urn:schemas-upnp-org:service-1-0"><actionList>'
        + action("AddPortMapping", MAPPING_ARGS)
        + action("DeletePortMapping", MAPPING_ARGS[:3])
        + action("GetExternalIPAddress", [("NewExternalIPAddress", "out")])
        + "</actionList></scpd>")

lock = threading.Lock()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def reply(self, body, status=200):
        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", 'text/xml; charset="utf-8"')
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path == "/desc.xml":
            self.reply(DESC)
        elif self.path == "/scpd.xml":
            self.reply(SCPD)
        else:
            self.reply("", 404)

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0))).decode()
        name = self.headers.get("SOAPAction", "").strip('"').split("#")[-1]
        args = dict(re.findall(r"<(New\w+)>([^<]*)</\1>", body))
        with lock, open(log_path, "a") as f:
            f.write(name + " " + " ".join(f"{k}={v}" for k, v in sorted(args.items())) + "\n")
        inner = f"<NewExternalIPAddress>{external_ip}</NewExternalIPAddress>" if name == "GetExternalIPAddress" else ""
        self.reply('<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
                   's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body>'
                   f'<u:{name}Response xmlns:u="{SERVICE}">{inner}</u:{name}Response></s:Body></s:Envelope>')


def ssdp():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", ssdp_port))
    while True:
        data, addr = s.recvfrom(2048)
        if data.startswith(b"M-SEARCH"):
            st = re.search(rb"ST:\s*(\S+)", data)
            s.sendto(b"HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=120\r\nEXT:\r\n"
                     + f"LOCATION: http://127.0.0.1:{http_port}/desc.xml\r\n".encode()
                     + b"ST: " + (st.group(1) if st else b"upnp:rootdevice") + b"\r\nUSN: uuid:fake::igd\r\n\r\n", addr)


threading.Thread(target=ssdp, daemon=True).start()
HTTPServer(("127.0.0.1", http_port), Handler).serve_forever()
