/* network honeypot:

 - list 'clients' doing scans of specified ports in a blacklist-file
 - whitelist clients opening ports in a preconfigured pattern (optional)

 Monitor predefined ports and put clients that try to scan them
 on a blacklist-file.

 This blacklist can be read by other apps to decide whether to
 react to a connection attempt or not. Good users know your
 app's portnumber and don't scan your machine for weaknesses.

 Check whitelist first. When client found, ignore blacklist.
 White clients will be in both lists.

 Run this app in a separate process.

 Attention:
 - Using port numbers below 1025 need admin rights. Don't run an
 app with admin rights unless your really know what it implies.

 - Make sure the ports are forewarded to your server by your
 router.

 - It may happen that you lock out users from shared or re-used
 IP addresses.

 Depending on your use-case, this may be no problem when your
 users are from enterprises with administered networks, where
 portscans are usually intercepted.

 If many private users sit behind a single NAT router, one bad
 guy may lock out many good users (...bad company is never good)
 since all use the same IP-address. Shorter penaltyTimespan may
 be helpful in this case.

 ...and yes, no node packages required. It's possible.

 History: (use semver)
 V01.00.00 12-03-2018 VK Initial release, have fun
*/

"use strict";

// get libs
const net = require("net"); // =portstuff

// get configuration from a separate file
let config = require("./config.js");
let BlackWhiteList = require("./BlackWhiteList.js");

// change this if you don't want console output
const myConsole = console;

/* to establish own logging, uncomment the following:
const util = require('util');

const myConsole = {
  log: function(...args) {
    let msg = util.format.apply(null, args);
    debugger // your turn to do something with the message
  },
  error: function(...args) {
    let msg = util.format.apply(null, args);
    debugger // your turn to do something with the message
  }
};
*/

/**
 * main - main entry into the program
 *
 * @return {undefined}
 */
const main = () => {

  // create list objects,
  // - specify filenames, configuration & logging function
  // - load content from file
  const blackList = new BlackWhiteList(config.blacklistFileName, config, myConsole);

  // default = no whitelist
  let whiteList = false;

  // portsequence configured -> establish whitelist
  if (config.whiteSequence.length)
    whiteList = new BlackWhiteList(config.whitelistFileName, config, myConsole);

  /**
   * connectionListener - CB called when a socket is opened
   *  1. update/add client in black- &| white-list
   *  2. close socket
   *
   * @param  {object} socket socket that was opened
   * @return {undefined}
   */
  const connectionListener = (socket) => {

    let client = blackList.find(socket.remoteAddress);

    // not found -> add
    if (client === undefined) {

      // new client -> add
      client = blackList.add(socket);

    } else {

      // client is known -> update record
      blackList.update(socket, client);

      // whitelisting activated -> check whether sequence matches and add to whitelist
      if (whiteList)
        whiteList.checkAddWhiteClient(socket, client);

    }

    blackList.save();

    myConsole.log("connected:", client);

    // let (bad?) client wait an unpredictable time
    setTimeout(() => {

        try {

          // send fake stuff & close socket again
          socket.end("OK " + Date.now() % 1000);
          //socket.end(); // = no answer, will make some browsers retry 10x

        } catch (err) {

          // ignore all errors here
          // the client may already have closed the connection
          // myConsole.error(err);

        }

      },
      500 + Math.random() * 1000
    );

  };

  /**
   * serverErrHandler - cb for server errors
   *
   * @param  {object} err error
   * @return {undfined}
   */
  const serverErrHandler = (err) => {

    // port maybe already open -> show
    if (err.code === "EACCES") {
      myConsole.log("can not open port %d, continuing with other ports", err.port);
    }

    myConsole.error(err);

  };

  // now start a server for each port monitored
  config.listenTo.forEach((port, index) => {

    // prepare an object that replaces the plain port number
    let entry = {
      port: port
    };

    // start a new server for this port...
    entry.server = net.createServer(connectionListener)
      .on("error", serverErrHandler);

    myConsole.log("opening port", port);

    // ...and make it listen
    entry.server.listen({
      port: port,
      exclusive: true
    });

    // replace plain port number by new object
    config.listenTo[index] = entry;

  });

  // periodically....
  setInterval(() => {

    // ...remove outdated entries if outdated
    blackList.removeOutdatedAndSave();

    // maintaining whitelist -> ...remove outdated entries if outdated
    if (whiteList)
      whiteList.removeOutdatedAndSave();

  }, config.penaltyTimespanMsec);

};

// explain what you do
myConsole.log("\nnetwork honeypot V1.0.0 by Volker Kinkelin, configuration is\n%o\n", config);

// now start the whole thing
main();

// give reason for confidence ;)
myConsole.log("\n...started.");
