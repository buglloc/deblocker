# Intro

Due to a massive censorship on the both sides of  the Russian "glass wall", I want to have some semi/fully automatic solution to bypas them. This is it :)

DeBlocker is a simple and fully automatic service for generating eBGP prefixes of blocked "sites" that you use.

# How it works
A flowchart is worth a thousand words so let's begin from it:
![](./assets/deblocker.svg)

As you can see deblocker has a couple of parts:
  - DNS server that:
    * exports A/AAAA answers into BGP if we think that requested _site_ must go over VPN
    * schedules HTTPS site checker to make a decision
  - HTTPS checker just make two HTTP requests - one over VPN interface and one over direct interface. After that, makes decision.
  - BGP server that exports "blocked" prefixes from HTTPS checker or DNS server

So when I execute `curl https://docs.splunk.com`:
  - `curl` resolves `docs.splunk.com` through DeBlocker that:
    * checks it (spoiler: must choose the VPN)
    * adds eBGP path for all of the IP addresses that points to `*.splunk.com`
  - and makes a TCP connection that routed over VPN
  - that's all, pretty simple

Of course sometimes I need to send request one more time, but this is not annoying me.
