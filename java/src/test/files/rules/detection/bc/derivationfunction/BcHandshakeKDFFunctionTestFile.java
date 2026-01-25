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
package com.ibm.plugin.rules.detection.bc.derivationfunction;

import java.security.SecureRandom;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.engines.EthereumIESEngine;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;

public class BcHandshakeKDFFunctionTestFile {

    public static void main(String[] args) {
        // Define the curve parameters (e.g., secp256k1 for Ethereum)
        ECDomainParameters curveParams = null;

        // Generate sender's key pair
        ECKeyPairGenerator keyPairGenerator = new ECKeyPairGenerator();
        ECKeyGenerationParameters keyGenParams =
                new ECKeyGenerationParameters(curveParams, new SecureRandom());
        keyPairGenerator.init(keyGenParams);

        // Define the HandshakeKDFFunction using EthereumIESEngine
        int counterStart = 1; // Starting value for the counter
        Digest digest = new SHA256Digest(); // Noncompliant {{(MessageDigest) SHA-256}}
        EthereumIESEngine.HandshakeKDFFunction kdfFunction =
                new EthereumIESEngine.HandshakeKDFFunction(counterStart, digest);
        // Noncompliant@-1 {{(KeyDerivationFunction) KDF2}}

        // ...
    }
}
