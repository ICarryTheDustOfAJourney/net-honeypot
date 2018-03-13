# net-honeypot
An application monitoring TCP-ports to find out who's foe and who's friend.
## Purpose
Small app to
- blacklist visitors when they scan pre-defined ports
- whitelist visitors when they open ports in a pre-defined sequence

May be useful to
- hide your service from visitors scanning your ports
- whitelist visitors after they opened ports in a pre-defined sequence

One can understand a port number (or a sequence) as a key to an otherwise hidden service.
Friendly users usually know your service's port number by heart ;) (...or bookmark).

## Installation
cd into installation directory, then

```
npm install net-honeypot
```
(...yes, this app needs no other packages)

## Usage
- edit config.js to match your needs (self-explaining, port# etc.)
- start app with
```
node index.js <enter>
```

The black-/white-list files (JSON, names specified in config.js) will be updated and have to be read by your service, eg prior to serviceing log-in requests.

After a (adjustable) time-out period, the visitors disappear from both lists.

Make sure the ports are forewarded to your machine. Ports < 2025 need admin-rights. Not recommended.

## Limitations
It may (rarely) happen that by blocking IP-addresses even friendly users are locked-out, when they use the same address as a bad guy (eg in NAT-scenarios). After a short period the lists are emptied, so a friendly re-try may resolve this.
