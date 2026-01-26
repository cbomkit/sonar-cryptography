/*
 * SonarQube Cryptography Plugin
 * Copyright (C) 2024 IBM
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */
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
        OAEPEncoding cipher = new OAEPEncoding(engine, new SHA3Digest()); // Noncompliant {{(MessageDigest) SHA-3}} {{(PublicKeyEncryption) RSA-OAEP}}

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
