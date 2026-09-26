const tls = require('tls');
const ctx = tls.createSecureContext({ minVersion: 'TLSv1.2' });
const server = tls.createServer({ minVersion: 'TLSv1.2' });
tls.connect({ host: 'localhost', port: 443, rejectUnauthorized: false }, () => {});
