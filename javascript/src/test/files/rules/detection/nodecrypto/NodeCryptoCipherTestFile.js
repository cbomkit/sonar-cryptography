const crypto = require('crypto');
const key = Buffer.alloc(32);
const iv = Buffer.alloc(16);
const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
cipher.update('data');
const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
