# libjuice - UDP Interactive Connectivity Establishment

[![License: MPL 2.0](https://img.shields.io/badge/License-MPL_2.0-blue.svg)](https://www.mozilla.org/en-US/MPL/2.0/)
[![Build and test](https://github.com/paullouisageneau/libjuice/actions/workflows/build.yml/badge.svg)](https://github.com/paullouisageneau/libjuice/actions/workflows/build.yml)
[![Packaging status](https://repology.org/badge/tiny-repos/libjuice.svg)](https://repology.org/project/libjuice/versions)
[![Latest packaged version](https://repology.org/badge/latest-versions/libjuice.svg)](https://repology.org/project/libjuice/versions)
[![Gitter](https://badges.gitter.im/libjuice/community.svg)](https://gitter.im/libjuice/community?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)
[![Discord](https://img.shields.io/discord/903257095539925006?logo=discord)](https://discord.gg/jXAP8jp3Nn)

libjuice :lemon::sweat_drops: (_JUICE is a UDP Interactive Connectivity Establishment library_) allows to open bidirectionnal User Datagram Protocol (UDP) streams with Network Address Translator (NAT) traversal.

The library is a simplified implementation of the Interactive Connectivity Establishment (ICE) protocol, client-side and server-side, written in C without dependencies for multiple platforms, including GNU/Linux, Android, FreeBSD, Apple macOS, iOS, and Microsoft Windows. The client supports only a single component over UDP per session in a standard single-gateway network topology, as this should be sufficient for the majority of use cases nowadays.

libjuice is licensed under MPL 2.0, see [LICENSE](https://github.com/paullouisageneau/libjuice/blob/master/LICENSE).

libjuice is available on [AUR](https://aur.archlinux.org/packages/libjuice-git) and [vcpkg](https://vcpkg.io/en/getting-started). Bindings are available for [Rust](https://github.com/VollmondT/juice-rs).

For a STUN/TURN server application based on libjuice, see [Violet](https://github.com/paullouisageneau/violet).

## Compatibility

The library implements a simplified full ICE agent ([RFC5245](https://www.rfc-editor.org/rfc/rfc5245.html) then [RFC8445](https://www.rfc-editor.org/rfc/rfc8445.html)) featuring:
- STUN protocol ([RFC5389](https://www.rfc-editor.org/rfc/rfc5389.html) then [RFC8489](https://www.rfc-editor.org/rfc/rfc8489.html))
- TURN relaying ([RFC5766](https://www.rfc-editor.org/rfc/rfc5766.html) then [RFC8656](https://www.rfc-editor.org/rfc/rfc8656.html))
- TCP candidates ([RFC6544](https://www.rfc-editor.org/rfc/rfc6544.html))
- ICE Consent freshness ([RFC7675](https://www.rfc-editor.org/rfc/rfc7675.html))
- ICE Patiently Awaiting Connectivity ([RFC 8863](https://www.rfc-editor.org/rfc/rfc8863.html))
- SDP-based interface ([RFC8839](https://www.rfc-editor.org/rfc/rfc8839.html))
- IPv4 and IPv6 dual-stack support
- Optional multiplexing on a single UDP port

The limitations compared to a fully-featured ICE agent are:
- Only UDP is supported as transport protocol and other protocols are ignored.
- Only one component is supported, which is sufficient for WebRTC Data Channels and multiplexed RTP+RTCP.
- Without a proxy, [RFC8828](https://www.rfc-editor.org/rfc/rfc8828) mode 2 is supported (default route + all local addresses).
- Optional SOCKS5 UDP proxy support implements the UDP portion of [RFC8828 Section 5.2](https://www.rfc-editor.org/rfc/rfc8828.html#section-5.2), mode 4 (force proxy), using [RFC1928](https://www.rfc-editor.org/rfc/rfc1928) UDP ASSOCIATE and optional [RFC1929](https://www.rfc-editor.org/rfc/rfc1929) authentication.

It also implements a lightweight STUN/TURN server ([RFC8489](https://www.rfc-editor.org/rfc/rfc8489.html) and [RFC8656](https://www.rfc-editor.org/rfc/rfc8656.html)). The server can be disabled at compile-time with the `NO_SERVER` flag.

### SOCKS5 UDP proxy

Set the proxy before setting the remote description or gathering candidates:

```c
juice_socks5_proxy_t proxy = {
    .host = "127.0.0.1",
    .port = 1080,
};
if (juice_set_socks5_proxy(agent, &proxy) != JUICE_ERR_SUCCESS) {
    // Handle unsupported or invalid proxy configuration.
}
```

The proxy must support UDP ASSOCIATE. All agent UDP traffic (STUN, ICE connectivity checks, TURN and application data) uses the association; local host candidates are not advertised. Proxy negotiation failure or loss of the TCP control connection fails the agent without a direct fallback. The configuration is copied by the agent. Set both `username` and `password` for authentication.

This option currently supports polling concurrency mode and UDP only; ICE-TCP and other concurrency modes are rejected. Gathering performs synchronous proxy negotiation with a five-second I/O deadline; local hostname resolution may take longer. Hostnames are resolved locally, and UDP response headers must contain numeric addresses. This is not full RFC8828 mode 4 support: there is no proxied TCP fallback or proxy-side DNS resolution.

## Dependencies

None!

Optionally, [Nettle](https://www.lysator.liu.se/~nisse/nettle/) can provide SHA1 and SHA256 algorithms instead of the internal implementation.

## Building

### Clone repository

```bash
$ git clone https://github.com/paullouisageneau/libjuice.git
$ cd libjuice
```

### Build with CMake

The CMake library targets `libjuice` and `libjuice-static` respectively correspond to the shared and static libraries. The default target will build the library and tests. It exports the targets with namespace `LibJuice::LibJuice` and `LibJuice::LibJuiceStatic` to link the library from another CMake project.

#### POSIX-compliant operating systems (including Linux and Apple macOS)

```bash
$ cmake -B build
$ cd build
$ make -j2
```

The option `USE_NETTLE` allows to use the Nettle library instead of the internal implementation for HMAC-SHA1:
```bash
$ cmake -B build -DUSE_NETTLE=1
$ cd build
$ make -j2
```

#### Microsoft Windows with MinGW cross-compilation

```bash
$ cmake -B build -DCMAKE_TOOLCHAIN_FILE=/usr/share/mingw/toolchain-x86_64-w64-mingw32.cmake # replace with your toolchain file
$ cd build
$ make -j2
```

#### Microsoft Windows with Microsoft Visual C++

```bash
$ cmake -B build -G "NMake Makefiles"
$ cd build
$ nmake
```

### Build directly with Make (Linux only)

```bash
$ make
```

The option `USE_NETTLE` allows to use the Nettle library instead of the internal implementation for HMAC-SHA1:
```bash
$ make USE_NETTLE=1
```

## Example

See [test/connectivity.c](https://github.com/paullouisageneau/libjuice/blob/master/test/connectivity.c) for a complete local connection example.

See [test/server.c](https://github.com/paullouisageneau/libjuice/blob/master/test/server.c) for a server example.

## Contributing

See [CONTRIBUTING.md](https://github.com/paullouisageneau/libjuice/blob/master/CONTRIBUTING.md) for contribution guidelines.

