const crypto = require('crypto');
crypto.pbkdf2('password', 'salt', 100000, 64, 'sha512', () => {});
crypto.scrypt('password', 'salt', 64, () => {});
crypto.hkdf('sha256', Buffer.alloc(32), Buffer.alloc(16), Buffer.from('info'), 32, () => {});
