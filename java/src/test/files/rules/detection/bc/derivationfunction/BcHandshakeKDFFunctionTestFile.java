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
