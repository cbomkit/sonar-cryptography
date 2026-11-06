import * as crypto from 'node:crypto';

interface Payload {
    body: string;
}

function hashSequential(payload: Payload): string {
    const hash: crypto.Hash = crypto.createHash('sha256');
    hash.update(payload.body);
    return hash.digest('hex');
}

function hashChained(payload: Payload): string {
    return crypto.createHash('sha512').update(payload.body).digest('hex');
}

function hashNextToUnrelatedUpdate(logger: { update(s: string): void }): string {
    const digester = crypto.createHash('md5');
    logger.update('not a hash call');
    digester.update('data');
    return digester.digest('hex');
}
