const crypto = require('crypto');
const dh = crypto.createDiffieHellman(2048);
const ecdh = crypto.createECDH('secp256k1');
dh.generateKeys();
ecdh.generateKeys();
