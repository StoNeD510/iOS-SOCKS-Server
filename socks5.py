#!python3
# Socks5/HTTP Proxy server for Pythonista by @nneonneo
# Pretty statistics view and IPv6 support added by @philrosenthal

import ipaddress
import logging
import socket
import threading

from lib.socks5_server import AsyncSocks5Handler
from lib.http_proxy_server import AsyncHTTPProxyHandler
from lib.proxy_server import AsyncProxyServer
from lib.status import StatusMonitor


#needed for backgrounding
import os
import base64
import tempfile
from objc_util import *
from time import sleep
from datetime import datetime


logging.basicConfig(level=logging.ERROR)

# IP over which the proxy will be available (probably WiFi IP)
PROXY_HOST = "172.20.10.1"
# IP over which the proxy will attempt to connect to the Internet
CONNECT_HOST_IPV4 = "0.0.0.0"
CONNECT_HOST_IPV6 = None
# Time out connections after being idle for this long (in seconds)
IDLE_TIMEOUT = 1800

LISTEN_HOST = "0.0.0.0"
SOCKS_PORT = 9876
HTTP_PORT = 9877
WPAD_PORT = 8088

###########ENABLE BACKGROUNDING#######

# "Imports"
AVAudioSession = ObjCClass('AVAudioSession')
AVPlayer = ObjCClass('AVPlayer')
AVPlayerItem = ObjCClass('AVPlayerItem')
NSURL = ObjCClass('NSURL')
AVPlayerLooper = ObjCClass('AVPlayerLooper')
AVQueuePlayer = ObjCClass('AVQueuePlayer')
NSNotificationCenter = ObjCClass('NSNotificationCenter')
CLLocationManager = ObjCClass('CLLocationManager')
NSData = ObjCClass('NSData')

# Silent MP3 embedded as base64 — no download, no file on disk required.
# 50 x valid MPEG1 Layer3 silent frames (~0.6 s); AVQueuePlayer loops it forever.
_SILENCE_B64 = (
    '//uQBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    'AAAAP/7kAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    'AAAAD/+5AEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    'AAAAAAAAAA//uQBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    'AAAAAAAAP/7kAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    'AAAAAAAD/+5AEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    'AAAAAAAAAAA//uQBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    'AAAAAAAAAP/7kAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    'AAAAAAAD/+5AEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    'AAAAAAAAAAA//uQBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    'AAAAAAAAAP/7kAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    'AAAAAAAD/+5AEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    'AAAAAAAAAAA//uQBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    'AAAAAAAAAP/7kAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    'AAAAAAAD/+5AEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    'AAAAAAAAAAA//uQBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    'AAAAAAAAAP/7kAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    'AAAAAAAD/+5AEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    'AAAAAAAAAAA//uQBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    'AAAAAAAAAP/7kAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    'AAAAAAAD/+5AEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    'AAAAAAAAAAA//uQBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    'AAAAAAAAAP/7kAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    'AAAAAAAD/+5AEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    'AAAAAAAAAAA//uQBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    'AAAAAAAAAP/7kAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    'AAAAAAAD/+5AEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    'AAAAAAAAAAA//uQBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    'AAAAAAAAAP/7kAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    'AAAAAAAD/+5AEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    'AAAAAAAAAAA//uQBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    'AAAAAAAAAP/7kAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=='
)

# Write the embedded MP3 to a temp file once so AVPlayerItem can reference it via URL.
# This avoids any network call and is guaranteed to work on first run.
_mp3_data = base64.b64decode(_SILENCE_B64)
_mp3_path = os.path.join(tempfile.gettempdir(), 'socks5_silence.mp3')
with open(_mp3_path, 'wb') as _f:
    _f.write(_mp3_data)

# Set Pythonista app to play non-blocking, 'mixed with others' sounds
# Options: MixWithOthers (0x1) | DuckOthers (0x2) — ducks other audio instead of being killed by it
audio_session = AVAudioSession.sharedInstance()
audio_session.setCategory_withOptions_error_('AVAudioSessionCategoryPlayback', 0x1 | 0x2, None)
audio_session.setActive_error_(True, None)

sound = NSURL.fileURLWithPath_(_mp3_path)
item = AVPlayerItem.playerItemWithURL_(sound)

#assign array with item to queueplayer
loopingItem = AVQueuePlayer.alloc().initWithItems([item])
#init the looper
looper = AVPlayerLooper.playerLooperWithPlayer_templateItem_(loopingItem, item)

#begin looping play back
loopingItem.play()

########## AUDIO KEEPALIVE POLL ##########
# Poll the player from a background thread. If rate drops to 0 we reactivate
# the audio session and resume playback.
def _audio_keepalive_loop():
    while True:
        try:
            sleep(10)
            try:
                rate = float(loopingItem.rate())
            except Exception:
                rate = 0.0
            if rate == 0.0:
                print('[keepalive] player stopped, reactivating + resuming')
                try:
                    audio_session.setActive_error_(True, None)
                except Exception:
                    pass
                try:
                    loopingItem.play()
                except Exception as ex:
                    print('[keepalive] play() failed: %s' % ex)
        except Exception as ex:
            print('[keepalive] poll error: %s: %s' % (type(ex).__name__, ex))
            sleep(15)

_keepalive_thread = threading.Thread(target=_audio_keepalive_loop)
_keepalive_thread.daemon = True
_keepalive_thread.start()

########## LOCATION-BASED KEEPALIVE ##########
# Low-accuracy background location updates keep the process alive even when
# audio gets fully yanked (e.g. during an actual phone call). This is best-effort
# — if Pythonista lacks the "location" background mode entitlement, the
# setAllowsBackgroundLocationUpdates_ call will raise an ObjC exception that
# we cannot catch from Python, so we probe capabilities first.
_loc_manager = None
try:
    _loc_manager = CLLocationManager.alloc().init()
    _loc_manager.setDesiredAccuracy_(3000.0)   # kCLLocationAccuracyKilometer
    _loc_manager.setDistanceFilter_(99999.0)
    try:
        _loc_manager.requestAlwaysAuthorization()
    except Exception:
        pass
    _loc_manager.setAllowsBackgroundLocationUpdates_(True)
    print('[keepalive] background location mode enabled')
    try:
        _loc_manager.setPausesLocationUpdatesAutomatically_(False)
    except Exception:
        pass
    _loc_manager.startUpdatingLocation()
    print('[keepalive] location updates started')
except Exception as ex:
    print('[keepalive] failed to start location manager: %s' % ex)
    _loc_manager = None

#########################################


def is_globally_routable(ipv6_address):
    non_routable_networks = [
        "ff00::/8",  # Multicast address range
        "fe80::/10",  # Link-local address range
        "fc00::/7",  # Unique local address range
        "::/8",  # Unspecified address range
        "2001:db8::/32",  # Documentation address range
        "2001::/32",  # Teredo address range
        "2002::/16",  # 6to4 address range
        "ff02::/16",  # Link-local multicast address range
    ]
    for network in non_routable_networks:
        if ipaddress.ip_address(ipv6_address) in ipaddress.ip_network(network):
            return False
    return True


try:
    # TODO: configurable DNS (or find a way to use the cell network's own DNS)
    import dns.asyncresolver

    resolver = dns.asyncresolver.Resolver(configure=False)
    resolver.nameservers += [
        "1.0.0.1",
        "1.1.1.1",
        "8.8.8.8",
        "2606:4700:4700::1111",
        "2606:4700:4700::1001",
        "2001:4860:4860::8844",
    ]
except ImportError:
    # pip install dnspython
    print("Warning: dnspython not available; falling back to system DNS")
    resolver = None

try:
    # We want the WiFi address so that clients know what IP to use.
    # We want the non-WiFi (cellular?) address so that we can force network
    #  traffic to go over that network. This allows the proxy to correctly
    #  forward traffic to the cell network even when the WiFi network is
    #  internet-enabled but limited (e.g. firewalled)

    from collections import defaultdict

    from lib import ifaddrs

    initial_output = ""
    ipv4_output = ""
    ipv6_output = ""

    interfaces = ifaddrs.get_interfaces()

    iftypes = defaultdict(list)
    for iface in interfaces:
        if not iface.addr:
            continue
        if iface.name.startswith("lo"):
            continue
        # XXX implement better classification of interfaces
        if iface.name.startswith("en"):
            iftypes["en"].append(iface)
        elif iface.name.startswith("bridge"):
            iftypes["bridge"].append(iface)
        elif iface.name.startswith("utun"):
            # VPN tunnel interface (e.g. an on-device VPN app/profile).
            # Never treat this as the "cell" interface to bind to directly --
            # binding a raw socket to the tunnel's own address doesn't get
            # forwarded by the network extension. When a VPN is active we
            # want outgoing connections to use the default route (the VPN)
            # instead of forcing a specific interface.
            iftypes["vpn"].append(iface)
        else:
            iftypes["cell"].append(iface)

    if iftypes["bridge"]:
        iface = next(
            (
                iface
                for iface in iftypes["bridge"]
                if iface.addr.family == socket.AF_INET
            ),
            None,
        )
        if iface:
            initial_output = (
                "Assuming proxy will be accessed over hotspot (%s) at %s\n"
                % (iface.name, iface.addr.address)
            )
            PROXY_HOST = iface.addr.address
    elif iftypes["en"]:
        iface = next(
            (iface for iface in iftypes["en"] if iface.addr.family == socket.AF_INET),
            None,
        )
        if iface:
            initial_output += (
                "Assuming proxy will be accessed over WiFi (%s) at %s\n"
                % (iface.name, iface.addr.address)
            )
            PROXY_HOST = iface.addr.address
    else:
        initial_output += (
            "Warning: could not get WiFi address; assuming %s\n" % PROXY_HOST
        )

    if iftypes["vpn"]:
        # A VPN tunnel is active. Don't force-bind to the raw cellular
        # interface -- leave CONNECT_HOST_IPV4/6 at their defaults so
        # outgoing connections take the default route, which is now the
        # VPN tunnel. This is required for "proxy to phone, then through
        # the VPN" to actually route through the tunnel instead of
        # bypassing it (or binding to the tunnel's own address, which the
        # network extension won't forward).
        ipv4_output += "VPN tunnel active (%s); using default route instead of binding to a specific interface\n" % (
            iftypes["vpn"][0].name,
        )
    elif iftypes["cell"]:
        iface_ipv4 = next(
            (iface for iface in iftypes["cell"] if iface.addr.family == socket.AF_INET),
            None,
        )
        iface_ipv6 = None

        if iface_ipv4:
            iface_ipv4.addr.address
            ipv4_output += "Will connect to IPv4 servers over interface %s at %s\n" % (
                iface_ipv4.name,
                iface_ipv4.addr.address,
            )
            CONNECT_HOST_IPV4 = iface_ipv4.addr.address

            # Create a list of all IPv6 addresse that are globally routable and match the IPv4 interface
            iface_ipv6_list = [
                iface
                for iface in iftypes["cell"]
                if iface.addr.family == socket.AF_INET6
                and iface.addr.address
                and is_globally_routable(iface.addr.address)
                and iface.name == iface_ipv4.name
            ]

            # Select the last IPv6 address to select the temporary address for reduced tracking
            iface_ipv6 = iface_ipv6_list[-1] if iface_ipv6_list else None

        if iface_ipv6 is None:
            # Create a list of all IPv6 addresses that are globally routable
            iface_ipv6_list = [
                iface
                for iface in iftypes["cell"]
                if iface.addr.family == socket.AF_INET6
                and iface.addr.address
                and is_globally_routable(iface.addr.address)
            ]

            # Select the last IPv6 address to select the temporary address for reduced tracking
            iface_ipv6 = iface_ipv6_list[-1] if iface_ipv6_list else None

        if iface_ipv6:
            iface_ipv6.addr.address
            ipv6_output += "Will connect to IPv6 servers over interface %s at %s\n" % (
                iface_ipv6.name,
                iface_ipv6.addr.address,
            )
            # Test IPv6 connectivity
            test_socket = None
            try:
                test_socket = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
                test_socket.settimeout(5)
                test_socket.bind((iface_ipv6.addr.address, 0))
                test_socket.connect(("2606:4700:4700::1111", 80))
                CONNECT_HOST_IPV6 = iface_ipv6.addr.address
            except Exception as e:
                ipv6_output += (
                    "Failed to connect to 2606:4700:4700::1111 over IPv6 due to: %s\n"
                    % str(e)
                )
                CONNECT_HOST_IPV6 = None
            finally:
                if test_socket is not None:
                    test_socket.close()

    initial_output += ipv4_output + ipv6_output
    print(initial_output)
except Exception as e:
    logging.error("Address detection failed: %s: %s", (type(e).__name__, e))
    import traceback

    traceback.print_exc()

    interfaces = None


def create_wpad_server(hhost, hport, phost, pport):
    from http.server import BaseHTTPRequestHandler, HTTPServer

    class HTTPHandler(BaseHTTPRequestHandler):
        def do_HEAD(s):
            s.send_response(200)
            s.send_header("Content-type", "application/x-ns-proxy-autoconfig")
            s.end_headers()

        def do_GET(s):
            s.send_response(200)
            s.send_header("Content-type", "application/x-ns-proxy-autoconfig")
            s.end_headers()
            s.wfile.write(
                (
                    """
function FindProxyForURL(url, host)
{
   if (isInNet(host, "192.168.0.0", "255.255.0.0")) {
      return "DIRECT";
   } else if (isInNet(host, "172.16.0.0", "255.240.0.0")) {
      return "DIRECT";
   } else if (isInNet(host, "10.0.0.0", "255.0.0.0")) {
      return "DIRECT";
   } else {
      return "SOCKS5 %s:%d; SOCKS %s:%d";
   }
}
"""
                    % (phost, pport, phost, pport)
                )
                .lstrip()
                .encode()
            )

    HTTPServer.allow_reuse_address = True
    server = HTTPServer((hhost, hport), HTTPHandler)
    return server


def run_wpad_server(server):
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


def prompt_connection_mode() -> str:
    print("Select connection mode:")
    print("  1) Wi-Fi / Personal Hotspot (default)")
    print("  2) USB (usbmux tunnel via pymobiledevice3 on your computer)")
    try:
        choice = input("Mode [1/2, default 1]: ").strip()
    except (EOFError, OSError):
        choice = ""
    return "usbmux" if choice == "2" else "hotspot"


if __name__ == "__main__":
    import asyncio

    connection_mode = prompt_connection_mode()

    wpad_server = create_wpad_server(LISTEN_HOST, WPAD_PORT, PROXY_HOST, SOCKS_PORT)

    if connection_mode == "usbmux":
        initial_output += (
            "\nUSB (usbmux) mode selected.\n"
            "On your computer:\n"
            "  1. pip install pymobiledevice3\n"
            "  2. Plug in the phone via USB, trust the computer if prompted.\n"
            "  3. Run (in two terminals, or backgrounded):\n"
            "       pymobiledevice3 usbmux forward {socks} {socks}\n"
            "       pymobiledevice3 usbmux forward {http} {http}\n"
            "  4. Configure your computer's proxy to 127.0.0.1:{socks} (SOCKS)\n"
            "     or 127.0.0.1:{http} (HTTP).\n"
        ).format(socks=SOCKS_PORT, http=HTTP_PORT)
    else:
        initial_output += "PAC URL: http://{}:{}/wpad.dat\n".format(
            PROXY_HOST, WPAD_PORT
        )
        initial_output += "SOCKS Address: {}:{}\n".format(
            PROXY_HOST or LISTEN_HOST, SOCKS_PORT
        )
        initial_output += "HTTP Proxy Address: {}:{}\n".format(
            PROXY_HOST or LISTEN_HOST, HTTP_PORT
        )
    stats = StatusMonitor(initial_output)
    logging.getLogger().addHandler(stats)

    thread = threading.Thread(target=run_wpad_server, args=(wpad_server,))
    thread.daemon = True
    thread.start()

    async def main():
        server = AsyncProxyServer(
            AsyncSocks5Handler,
            listen_hosts=LISTEN_HOST,
            listen_port=SOCKS_PORT,
            traffic_stats=stats,
            resolver=resolver,
            connect_host_ipv4=CONNECT_HOST_IPV4,
            connect_host_ipv6=CONNECT_HOST_IPV6,
        )
        asyncio.create_task(server.run())

        server = AsyncProxyServer(
            AsyncHTTPProxyHandler,
            listen_hosts=LISTEN_HOST,
            listen_port=HTTP_PORT,
            traffic_stats=stats,
            resolver=resolver,
            connect_host_ipv4=CONNECT_HOST_IPV4,
            connect_host_ipv6=CONNECT_HOST_IPV6,
        )
        asyncio.create_task(server.run())

        await stats.render_forever()

    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        loopingItem.removeAllItems()
        print("Shutting down.")
        wpad_server.shutdown()
