/*  network honeypot configuration file

  change parameters to suit your needs here

*/
let config = {

  // max # of entries in blacklist
  maxEntries: 4096,

  // max length of access sequence stored
  maxSequenceLength: 10,

  // clients get off list after this time [msec]
  penaltyTimespanMsec: 1000 * 20, // = 20 seconds

  // where to save the list file(s)
  // content may change often, choose a fast location (RAM?)
  blacklistFileName: "./list_black.json",
  whitelistFileName: "./list_white.json",

  // port numbers to be monitored
  // attention: ports below 1025 need
  // node to run under admin-rights
  // careful with that! see
  // https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers#Well-known_ports
  listenTo: [2000, 2001, 2002, 2003, 2004],

  whiteSequence: [2001, 2003, 2000] // [] means no whitelist

};

module.exports = config;
