const crypto = require('crypto');
crypto.generateKey('aes', { length: 256 }, () => {});
crypto.generateKeyPair('rsa', { modulusLength: 2048 }, () => {});
crypto.createSecretKey(Buffer.alloc(32));
crypto.createPublicKey({ key: 'dummy' });
crypto.createPrivateKey({ key: 'dummy' });
