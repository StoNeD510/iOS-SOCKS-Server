# What

A simple HTTP/SOCKS proxy designed to run on Pythonista on iOS, letting you fake-tether your devices to a phone.

This is a fork of [nneonneo/iOS-SOCKS-Server](https://github.com/nneonneo/iOS-SOCKS-Server). See [Differences from upstream](#differences-from-upstream) below for what's changed.

# Installation

- Install Pythonista from the [App Store](https://apps.apple.com/us/app/pythonista-3/id1085978097). It's a paid app, but it's worth every penny if you are a power user.
- Download this repo as a zip from GitHub.
- Open the Files app, navigate to Downloads, and tap on the zip file to uncompress it.
- Move the resulting `iOS-SOCKS-Server` folder to the Pythonista iCloud directory
- Open Pythonista, navigate to iCloud, `iOS-SOCKS-Server` and open the `socks5.py` script.
- Optionally, you can tap on the wrench and select `Shortcuts...` to add the script to your home screen.

# Running

- Open the home screen shortcut (if you made one), or open the `socks5.py` script in Pythonista and hit Run.
- You'll be asked to pick a connection mode — see [Differences from upstream](#differences-from-upstream) for what each one means and when to use it.
- Point your devices at the PAC URL (also called script URL, script address, etc.), or configure them to use the SOCKS proxy listed.
    - For iOS devices: open Settings, tap on Wi-Fi, tap on the (i) icon next to the network, scroll down to HTTP Proxy, tap on Configure Proxy, select Automatic, and enter the PAC URL as displayed in Pythonista in the URL field (the URL will look like http://123.123.123.123:8080/wpad.dat).
    - For macOS: open System Preferences -> Network, click on Wi-Fi, hit Advanced..., and under Proxies check SOCKS Proxy and set the host:port to the SOCKS Address as displayed in Pythonista (this will be of the form 123.123.123.123:9876).
        - If you are using an ad-hoc Wi-Fi network (i.e. Wi-Fi menu -> Create Network), you will need to do some extra setup here. Under the TCP/IP tab, copy the existing 169.254.y.z IPv4 address, then switch Configure IPv4 to Manually, enter the 169.254.y.z IP address in both IPv4 Address and Router, and enter 255.255.0.0 as Subnet Mask. Under the DNS tab, add 169.254.y.z to the DNS Servers list.
        - Make sure you set proxy settings in any other application that is not using the system proxy settings.
    - For Windows or Linux, please follow the appropriate instructions for configuring a proxy on your system. It is recommended that you use the PAC URL if possible (also called a setup script or automatic configuration script). If you're using USB mode (see below), point the proxy at `127.0.0.1` and whatever local port you forwarded instead.
    - For Android: open Settings, Wi-Fi, select your network, expand the Advanced Settings, change the proxy setting to Manual, and enter the host and port for the *HTTP proxy*. Note that SOCKS proxy support on Android is limited, even when using the PAC URL, so the HTTP proxy is recommended.
        - Many applications on Android do not respect proxy settings, unfortunately, and in those cases you will have to configure the apps manually or use an app like Proxifier to force apps to use the proxy.

# Why

Recently, while travelling, I found out that Google Fi doesn't support tethering on iOS (I guess it's a feature they want to keep Android-exclusive or something?). Since my phone has a nice, fast, unblocked connection, I wanted to let my computer access it too.

I previously wrote [Socks5-iOS](https://github.com/nneonneo/socks5-ios) for doing exactly this, but it turned out to be quite cumbersome to deploy and modify. Plus, the app expires frequently (if you don't have an iOS developer account), which makes it annoying if you need it in a pinch. Enter Pythonista - an App Store app which puts a complete Python interpreter on iOS.

This script can be used to implement a functional alternative to tethering, which I refer to fake-tethering. Fake-tethering has some substantial advantages over standard iOS tethering. It works even when carriers ban tethering, and it bypasses limits set on tethering speed since all connections originate from the phone.

While it's easiest to use this with websites, it's actually possible to tunnel any TCP connection over a SOCKS proxy. For example, here's how you would proxy an SSH connection:

`ssh -o ProxyCommand='nc -X 5 -x <IP>:9876 %h %p' user@host`

# Differences from upstream

This fork adds a few things on top of the original, aimed at getting a laptop online through the phone's Wi-Fi (not just cellular) over a USB cable, without relying on Personal Hotspot:

## Connection mode selection

On startup, the script now prompts for a connection mode instead of relying purely on interface auto-detection:

- **Wi-Fi / Personal Hotspot** (original behavior) — the script auto-detects whichever interface (Hotspot bridge or Wi-Fi) your clients will reach it on and prints the SOCKS/HTTP/PAC addresses for that interface.
- **USB (usbmux tunnel)** — for reaching the proxy over a USB cable *without* enabling Personal Hotspot. On many iPhones, Personal Hotspot forces the Wi-Fi radio into AP broadcast mode, which disconnects it from your home/ambient Wi-Fi network entirely — so Hotspot mode can't be used if you want the phone to *stay* on Wi-Fi while relaying over USB. This mode instead prints instructions for forwarding a port over `usbmux` (the same USB transport iTunes/Xcode use), which works independently of Hotspot/AP state:
  1. `pip install pymobiledevice3` on your computer
  2. Plug in the phone, trust the computer if prompted
  3. `pymobiledevice3 usbmux forward 9876 9876` (and `9877 9877` for the HTTP proxy)
  4. Point your proxy config at `127.0.0.1:9876` (or `:9877`)

  Both modes use the same listener (the server already binds `0.0.0.0`), so the live traffic counters and connection stats work identically regardless of which one you pick.

## VPN-aware outbound routing

If an on-device VPN (WireGuard, OpenVPN, or any app using a `utun` NetworkExtension tunnel) is active when the script starts, outbound proxied connections are left on the OS's default route (the VPN tunnel) rather than being explicitly bound to the tunnel interface's own address — binding directly to a `utun` address doesn't get forwarded by the network extension, so the proxy would otherwise silently bypass the VPN. This means traffic flows `client -> proxy -> VPN tunnel -> underlying network (Wi-Fi or cellular) -> VPN server -> internet`, so all proxied traffic stays inside the VPN whenever one is active on the phone.

## Background keepalive

Pythonista scripts normally get suspended shortly after backgrounding or locking the screen, which kills the proxy. This fork keeps the script alive in the background by looping a silent audio track (`AVQueuePlayer`, mixed/ducked so it doesn't interrupt other audio) combined with low-accuracy background location updates as a secondary keepalive signal, with a watchdog thread that restarts playback if it ever stops.

## WPAD/PAC bugfix

Fixed the `wpad.dat` autodiscovery endpoint, which was returning a raw Python tuple instead of the `FindProxyForURL` PAC script and would throw on every request.

# Troubleshooting

## Doesn't work with an ad-hoc network on macOS

macOS appears to incorrectly assess the Internet as unreachable with an ad-hoc network, even if a proxy is configured. A workaround for this, tested on macOS 10.14, is described under [issue #1](https://github.com/nneonneo/iOS-SOCKS-Server/issues/1#issuecomment-583989079).
