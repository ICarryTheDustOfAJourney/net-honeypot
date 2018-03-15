# net-honeypot

A  [node](http://nodejs.org) application monitoring TCP-ports to find out who's foe and who's friend.

## Purpose

-   blacklist visitors when they scan pre-defined ports
-   whitelist visitors when they open ports in a pre-defined sequence

May be useful to

-   hide your service from bad visitors scanning your ports
-   optionally whitelist good visitors, after they opened ports in a pre-defined sequence
-   protect your webservice from malicious visitors

One can understand a port number (or a sequence) as a key to an otherwise hidden service.
Friendly users usually know your service's port number by heart (...or link or bookmark).

## Installation
cd into installation directory, then

```bash
    npm install net-honeypot
```
...yes, this app needs no other packages,

## Usage
```bash
    node index.js
```
## Test

Start it, then open <http://localhost:2000/>

You will see reactions on the commandline and two new files `list_black.json` and `list_white.json` will appear.

Depending on the browser you are using, you may see multiple attempts to open the port. FF shows the intentionally invalid, somewhat meaningless response and may re-try. Chrome shows an ERR_INVALID_HTTP_RESPONSE screen.

`list_black.json` will get an entry, file size increases. You can inspect the files using a non-locking viewer like FF.

Wait at least 20 seconds, then open

-   <http://localhost:2001/>
-   <http://localhost:2003/>
-   <http://localhost:2000/>

<b>each port exactly once and exactly in this sequence</b> as defined in config.js within 20 seconds.

You will see `list_white.json` grow for 20 seconds by the new white visitor's record, containing the timestamp, IP-address & last port opened.

Alternatively, telnet works as a (more obedient) test-visitor:
-   `telnet localhost 2001`
-   `telnet localhost 2003`
-   `telnet localhost 2000`

You will need to implement this behaviour into your client-app, when using whitelists.

The black-/white-list files (JSON, names specified in config.js) will be updated and have to be read by your service, eg prior to serviceing log-in requests.

After a (adjustable) time-out period, visitors disappear from both lists. Entries in `list_white.json` will also appear in `list_black.json`. Make sure decide upon the white list first in your service.

Now modify config.js to match your needs (self-explaining, port# etc.)

Make sure the ports are forewarded to your machine. Ports &lt; 2025 need node to run under admin-rights. Not recommended.

Developed & tested under Linux 4.4.0 and Node V8.10.0.

## Limitations

It may happen that by blocking IP-addresses even friendly users are locked-out, when they use the same address as a bad guy (eg in NAT-scenarios). After a short period the records are removed, so a patient re-try may resolve this.

Be careful when dealing with large # of visitors. Each needs an own record and thus ressources.

## License

  [MIT](LICENSE)
