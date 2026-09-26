const crypto = require('crypto');

const hash = crypto.createHash('md5');
hash.update('hello');
const digest = hash.digest('hex');

const hmac = crypto.createHmac('sha256', 'secret');
hmac.update('data');
