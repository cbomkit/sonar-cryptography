package com.ibm.plugin.rules.detection.bc.asymmetricblockcipher;

import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.BufferedAsymmetricBlockCipher;
import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.encodings.OAEPEncoding;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ParametersWithRandom;

public class BcBufferedAsymmetricBlockCipherTestFile {

    public static void main(String[] args) {
        // Initialize your asymmetric block cipher, for example RSA
        AsymmetricBlockCipher engine = new RSAEngine(); // Noncompliant {{(PublicKeyEncryption) RSA}}
        OAEPEncoding cipher = new OAEPEncoding(engine, new SHA3Digest()); // Noncompliant {{(MessageDigest) SHA3}} {{(PublicKeyEncryption) RSA-OAEP}}

        // Initialize a key for encryption/decryption
        AsymmetricKeyParameter key = null; // Initialize your asymmetric key (e.g., RSA key)

        // Wrap the asymmetric cipher in a buffered cipher
        BufferedAsymmetricBlockCipher bufferedCipher = new BufferedAsymmetricBlockCipher(cipher);
        // Noncompliant@-1 {{(PublicKeyEncryption) RSA-OAEP}}

        // Optionally, set encryption or decryption mode
        bufferedCipher.init(true, new ParametersWithRandom(key)); // For encryption

        // ...
    }
}
