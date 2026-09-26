const crypto = require('crypto');
const algorithm = 'sha256';
const hash = crypto.createHash(algorithm);
hash.update('data');
