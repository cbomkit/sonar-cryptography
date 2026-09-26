const crypto = require('crypto');
crypto.randomBytes(32);
crypto.randomFill(Buffer.alloc(32), () => {});
crypto.randomUUID();
