const crypto = require('crypto');
const sign = crypto.createSign('RSA-SHA256');
sign.update('message');
const verify = crypto.createVerify('RSA-SHA256');
verify.update('message');
