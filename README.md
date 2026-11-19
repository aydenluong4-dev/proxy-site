# 100 Girlfriends proxy

A small web proxy with a search bar at the top and a games library. No dependencies.

## Run it on your computer
1. Install Node.js 18 or newer from nodejs.org.
2. In this folder run:  `node server.js`
3. Open http://localhost:8080

## Put it online
You need a host that runs Node (Render, Railway, Fly.io, or a VPS). Upload this folder,
set the start command to `node server.js`, and the host gives you a web address.
It uses the PORT the host provides.

Optional settings (environment variables):
- ACCESS_CODE  Require a code. Visit  https://your-site/?code=YOURCODE  once on each device.
  Recommended, so strangers can't use (and burn the bandwidth of) your proxy.
- PORT         Default 8080.

## What it can and can't do
Works well: search results, news, wikis, most simple sites, the games library.
Often breaks: sites that need logins, YouTube and other heavy video or app-style sites.
Cookies aren't kept, so nothing stays logged in. Don't enter passwords or payment details
into pages loaded through any small proxy.
The server refuses to reach private or local network addresses.
