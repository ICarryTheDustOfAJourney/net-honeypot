/*  network honeypot configuration file

  change parameters to suit your needs here

*/
const fs = require("fs"); // =filestuff

"use strict";

// all functions related to the black &| white list(s)
class BlackWhiteList {

  /**
   * constructor - setup instance
   *
   * @param  {string} filename            name of file where to save list
   * @param  {object} myConfig            configuration object, see config.js
   * @param  {object} myConsole = console console logging object
   * @param  {bool} autoLoad = true     load file content (=sync!) upon initialisation
   */
  constructor(filename, myConfig, myConsole = console, autoLoad = true) {

    // where to save list in fs
    this.filename = filename;

    // establish err-logging functions ( .error())
    this.myConsole = myConsole;

    // save ref to configuration
    this.myConfig = myConfig;

    // the list of 'clients' trying to connect
    this.list = [];

    // load content from file wanted -> just do it
    if (autoLoad)
      this.load();

  }

  /**
   * save - save blacklist to a file
   * fileformat:
   *  [{"ts":1520873708984,"addr":"::ffff:192.168.2.51","ports":[43211,43211,43211,43211,43211,43211,43211,43211,43211,43211,43211],"count":20}, {,,,} ....]
   *      ts: timestamp of latest attempt
   *    addr: IP address [V6]
   *   ports: ports that were opened, in that order, FIFO shifting
   *   count: no of ports opened
   *
   * @return {undefined}
   */
  save(filename = this.filename) {

    try {

      const json = JSON.stringify(this.list);

      // don't async here, because file consistency will suffer
      // portscanners can wait
      fs.writeFileSync(filename, json);

    } catch (err) {

      this.myConsole.error(err);

    }

  }

  /**
   * load - load list from a file
   *
   * @param  {function} cb = false                      callback(err, data) after read
   * @return {undefined}
   */
  load(cb = false) {

    try {

      fs.readFile(this.filename, (err, data) => {

        if (!err && data) {
          try {

            this.list = JSON.parse(data);

          } catch (err) {

            this.myConsole.error(err);

          }

        }

        if (cb)
          cb(err, data);

      });

    } catch (err) {

      this.myConsole.error(err);

    }

    // get rid of old entries
    this.removeOutdatedAndSave();

  }

  /**
   * find - find an existing client in blacklist by its IP-address
   *
   * @param  {string} clientAddress ip-address to be found, IPV6 notation usually
   * @return {object | undefined}            the first client found or undefined
   */
  find(clientAddress, andRemove = false) {

    const findFunc = ({
      addr
    }) => addr === clientAddress;

    // just remove entry retval = true = found
    if (andRemove) {

      let foundIndex = this.list.findIndex(findFunc);

      if (foundIndex === -1)
        return false;

      this.list.splice(foundIndex, 1);
      return true;

    }

    return this.list.find(findFunc);

  }

  /**
   * add - add client to blacklist
   *
   * @param  {object} socket socket that was opened by client
   * @return {object}        client
   */
  add(socket) {

    let client = {
      ts: Date.now(), // = timestamp
      addr: socket.remoteAddress,
      ports: [socket.localPort],
      count: 1
    };

    // too many clients -> remove first
    if (this.list.length > this.myConfig.maxEntries)
      this.list.shift();

    this.list.push(client);

    return client;

  }

  /**
   * update - update an in blacklist existing client
   *
   * @param  {object} socket socket that was opened
   * @param  {object} client client to be updated
   * @return {undefined}
   */
  update(socket, client) {

    // update latest timestamp
    client.ts = Date.now();

    // update # of attempts
    client.count++;

    // store only the last maxSequenceLength attempts
    if (client.ports.length > this.myConfig.maxSequenceLength)
      client.ports.shift();

    // add latest to end
    client.ports.push(socket.localPort);


  }

  /**
   * removeOutdatedAndSave - remove clients from blacklist that are outdated
   *
   * @param  {number} maxAge = this.myConfig.penaltyTimespan msec after which a client is outdated
   * @return {undefined}
   */
  removeOutdatedAndSave(maxAge = this.myConfig.penaltyTimespanMsec) {

    const now = Date.now();
    const oldLength = this.list.length;

    this.list = this.list.filter(client => (now - client.ts) < maxAge);

    //  list changed -> save
    if (this.list.length !== oldLength)
      this.save();

  }

  /**
   * clientIsWhite - description
   *
   * @param  {object} client                               client to be tested
   * @param  {array} whiteSequence = config.whiteSequence  port sequence to be used for test
   * @return {bool}                    true, when white, false when black
   */
  clientIsWhite(client, whiteSequence = this.myConfig.whiteSequence) {

    // compare port sequence lengths for equality
    if (client.ports.length === whiteSequence.length) {

      // compare port sequence contents for equality
      if (JSON.stringify(client.ports) === JSON.stringify(whiteSequence))
        return true;

    }

    return false;

  }

  /**
   * checkAddWhiteClient - check & add a client to whitelist
   * when matching the access- pattern
   *
   * @param  {object} socket socket which was opened
   * @param  {object} client to be checked
   * @return {undefined}
   */
  checkAddWhiteClient(socket, client) {

    if (this.myConfig.whiteSequence.length < 1)
      return;

    // client matches pattern -> update whitelist
    if (this.clientIsWhite(client)) {

      // client already in list?
      let myClient = this.find(client.addr);

      // not found -> add
      if (myClient === undefined) {

        // new client -> add
        this.add(socket);

      } else {

        // client is known -> update record
        this.update(socket, myClient);

      }
      // change made -> save updated (white)list
      this.save();

    } else {

      // make sure client is taken off whitelist

      // found -> save updated (white)list
      if (this.find(client.addr, true) === true)
        this.save();

    }

  }

}

module.exports = BlackWhiteList;
