#!/usr/bin/env node

//
// Copyright 2020 DxOS.
//

const debug = require('debug');
const os = require('os');
const dnspacket = require('dns-packet');
const argv = require('optimist').argv;

const log = debug('dxos:mdns');
const ttl = 120;
const typeA = 'A';
const typeAAAA = 'AAAA';

const interfaces = [];
if (argv.interfaces) {
  interfaces.push(...argv.interfaces.split(','));
}

const getNetworkAddresses = (type) => {
  const family = typeAAAA === type ? 'IPv6' : 'IPv4'
  const allInterfaces = os.networkInterfaces();
  const addresses = [];
  const adapterNames = interfaces.length ? interfaces : Object.getOwnPropertyNames(allInterfaces);
  for (const adapterName of adapterNames) {
    const adapterInfo = allInterfaces[adapterName];
    if (adapterInfo) {
      addresses.push(...adapterInfo.filter(net => !net.internal && net.family === family));
    }
  }
  return addresses;
}

const hostnames = [];
if (argv.hostnames) {
  hostnames.push(...argv.hostnames.split(','));
} else {
  hostnames.push(os.hostname());
}

const mdns = require('mdns-server')({
  reuseAddr: true,
  ttl: 255,
  srcPort: 5353
})

mdns.on('query', (query) => {
  for (const question of query.questions) {
    if (question.type === typeA || question.type === typeAAAA) {
      const hostname = hostnames.find(name => name === question.name);
      if (hostname) {
        log('QUERY', query);

        const records = getNetworkAddresses(question.type).map((net) => {
          return {
            class: 1,
            flush: true,
            type: question.type,
            ttl,
            name: hostname,
            data: net.address
          };
        });

        const response = {
          type: 'response',
          flags: dnspacket.AUTHORITATIVE_ANSWER,
          answers: records
        };

        log('RESPONSE', response);
        mdns.respond(response);
      }
    }
  }
});
