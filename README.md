<div align="center">
  <br/>
  <img src="https://res.cloudinary.com/hyperglass/image/upload/v1593916013/logo-light.svg" width=300></img>
  <br/>
  <h3>The network looking glass that tries to make the internet better.</h3>
  <br/>  
  A looking glass is implemented by network operators as a way of providing customers, peers, or the general public with a way to easily view elements of, or run tests from the provider's network.
</div>

<hr/>

> **Fork notice** — This is a maintained fork of [thatmattlove/hyperglass](https://github.com/thatmattlove/hyperglass) with security hardening and operational fixes for production deployments. Upstream remains the project of record for documentation and general development; use **this** repository if you want the hardened query path, rate limiting, and related bugfixes below. We do not currently open PRs upstream — divergences live here on purpose.
>
> **Hardening & fixes in this fork (vs upstream `main`):**
>
> - **Query-target validation** against CLI injection and forbidden shell metacharacters
> - **Block `$(…)` / command substitution** on `linux_ssh` device drivers
> - **Require a reverse proxy** in front of the app (documented + compose typo fix)
> - **Shared Redis-backed rate limiter** for multi-worker deployments (not per-process only)
> - **Lower default query rate limit** (10) and make it env-configurable
> - **Litestar path-traversal CVE patch** and broader query-API DoS hardening
> - **Reject empty target lists** with 400 instead of 500; reset stale rule state
> - **Clean `ParsingError` surfaces** for Arista and FRR (no TypeError-masked 500s)
> - **Webhook validator** accepts raw dict input in `mode='before'` (upstream #282)
> - **Arista VRF-aware** builtin directives and BGP route VRF command fixes
> - **Reproducible Docker builds** from `requirements.lock`
>
> Upstream docs and the live demo still apply: [hyperglass.dev](https://hyperglass.dev). File fork-specific issues against [z23/hyperglass](https://github.com/z23/hyperglass/issues).

<div align="center">

[**Documentation**](https://hyperglass.dev)&nbsp;&nbsp;&nbsp;|&nbsp;&nbsp;&nbsp;[**Live Demo**](https://demo.hyperglass.dev/)&nbsp;&nbsp;&nbsp;|&nbsp;&nbsp;&nbsp;[**Upstream**](https://github.com/thatmattlove/hyperglass)

[![Frontend Tests](https://img.shields.io/github/actions/workflow/status/thatmattlove/hyperglass/frontend.yml?label=Frontend%20Tests&style=for-the-badge)](https://github.com/thatmattlove/hyperglass/actions/workflows/frontend.yml)
[![Backend Tests](https://img.shields.io/github/actions/workflow/status/thatmattlove/hyperglass/backend.yml?label=Backend%20Tests&style=for-the-badge)](https://github.com/thatmattlove/hyperglass/actions/workflows/backend.yml)

<br/>

hyperglass is intended to make implementing a looking glass too easy not to do, with the lofty goal of improving the internet community at large by making looking glasses more common across autonomous systems of any size.

</div>

### [Changelog](https://hyperglass.dev/changelog)

## Features

- BGP Route, BGP Community, BGP AS Path, Ping, & Traceroute, or [add your own commands](https://hyperglass.dev/configuration/directives).
- Full IPv6 support
- Customizable everything: features, theme, UI/API text, error messages, commands
- Built-in support for:
  - Arista EOS
  - BIRD
  - Cisco IOS
  - Cisco NX-OS
  - Cisco IOS-XR
  - FRRouting
  - Huawei VRP
  - Juniper Junos
  - Mikrotik
  - Nokia SR OS
  - OpenBGPD
  - TNSR
  - VyOS
- Configurable support for any other [supported platform](https://hyperglass.dev/platforms)
- Optionally access devices via an SSH proxy/jump server
- Access-list/prefix-list style query control to whitelist or blacklist query targets
- REST API with automatic, configurable OpenAPI documentation
- Modern, responsive UI built on [ReactJS](https://reactjs.org/), with [NextJS](https://nextjs.org/) & [Chakra UI](https://chakra-ui.com/), written in [TypeScript](https://www.typescriptlang.org/)
- Query multiple devices simultaneously
- Browser-based DNS-over-HTTPS resolution of FQDN queries

*To request support for a specific platform, please [submit a Github Issue](https://github.com/thatmattlove/hyperglass/issues/new) with the **feature** label.*

### [Get Started →](https://hyperglass.dev/installation)

## Community

- [Slack](https://netdev.chat/)
- [Telegram](https://t.me/hyperglasslg)

Any users, potential users, or contributors of hyperglass are welcome to join and discuss usage, feature requests, bugs, and other things.

**hyperglass is developed with the express intention of being free to the networking community**.

*However, if you're feeling particularly helpful or generous, small donations are welcome.*

[![Donate](https://img.shields.io/badge/Donate-blue.svg?logo=paypal&style=for-the-badge)](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=ZQFH3BB2B5M3E&source=url)

## Acknowledgements

hyperglass is built entirely on open-source software. Here are some of the awesome libraries used, check them out too!

- [Netmiko](https://github.com/ktbyers/netmiko)
- [Litestar](https://litestar.dev)
- [Pydantic](https://docs.pydantic.dev/latest/)
- [Chakra UI](https://chakra-ui.com/)

[![GitHub](https://img.shields.io/github/license/thatmattlove/hyperglass?color=330036&style=for-the-badge)](https://github.com/thatmattlove/hyperglass/blob/main/LICENSE)
