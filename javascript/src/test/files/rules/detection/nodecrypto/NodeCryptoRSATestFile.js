const crypto = require('crypto');
const data = Buffer.from('secret');
crypto.publicEncrypt({ key: 'dummy' }, data);
crypto.privateDecrypt({ key: 'dummy' }, data);
