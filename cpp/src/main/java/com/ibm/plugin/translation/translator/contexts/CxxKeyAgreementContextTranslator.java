/*
 * Sonar Cryptography Plugin
 * Copyright (C) 2024 PQCA
 *
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to you under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.ibm.plugin.translation.translator.contexts;

import com.ibm.engine.model.IValue;
import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.context.DetectionContext;
import com.ibm.engine.model.context.IDetectionContext;
import com.ibm.engine.rule.IBundle;
import com.ibm.mapper.IContextTranslation;
import com.ibm.mapper.model.Algorithm;
import com.ibm.mapper.model.EllipticCurve;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.KeyAgreement;
import com.ibm.mapper.model.KeyEncapsulationMechanism;
import com.ibm.mapper.model.PublicKeyEncryption;
import com.ibm.mapper.model.algorithms.AES;
import com.ibm.mapper.model.algorithms.ChaCha20Poly1305;
import com.ibm.mapper.model.algorithms.DH;
import com.ibm.mapper.model.algorithms.ECDH;
import com.ibm.mapper.model.algorithms.HKDF;
import com.ibm.mapper.model.algorithms.MLKEM;
import com.ibm.mapper.model.algorithms.RSA;
import com.ibm.mapper.model.algorithms.SHA2;
import com.ibm.mapper.model.algorithms.SM2;
import com.ibm.mapper.model.algorithms.SecP256r1MLKEM768;
import com.ibm.mapper.model.algorithms.SecP384r1MLKEM1024;
import com.ibm.mapper.model.algorithms.X25519;
import com.ibm.mapper.model.algorithms.X25519MLKEM768;
import com.ibm.mapper.model.algorithms.X448;
import com.ibm.mapper.model.algorithms.X448MLKEM1024;
import com.ibm.mapper.model.mode.GCM;
import com.ibm.mapper.utils.DetectionLocation;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.Optional;
import javax.annotation.Nonnull;

/**
 * Translator for C++ key agreement detection contexts.
 *
 * <p>This translator handles the translation of key agreement-related detection values (Diffie-
 * Hellman, ECDH, X25519/X448, ML-KEM, SM2) to the mapper model nodes. Values detected with the
 * context kind {@code KEM} are key encapsulation mechanism names, and values with the kind {@code
 * HPKE} are HPKE suites.
 */
public final class CxxKeyAgreementContextTranslator implements IContextTranslation<AstNode> {

    @Override
    public @Nonnull Optional<INode> translate(
            @Nonnull IBundle bundleIdentifier,
            @Nonnull IValue<AstNode> value,
            @Nonnull IDetectionContext detectionContext,
            @Nonnull DetectionLocation detectionLocation) {

        if (value instanceof ValueAction<AstNode>
                || value instanceof com.ibm.engine.model.Algorithm<AstNode>) {
            final String kind =
                    detectionContext instanceof DetectionContext context
                            ? context.get("kind").orElse("")
                            : "";
            return switch (kind) {
                case "KEM" -> kemByName(value.asString(), detectionLocation);
                case "HPKE" -> hpkeBySuite(value.asString(), detectionLocation);
                default -> byName(value.asString(), detectionLocation);
            };
        }

        return Optional.empty();
    }

    /** Names accepted by {@code EVP_KEM_fetch}. */
    @Nonnull
    private Optional<INode> kemByName(
            @Nonnull String rawName, @Nonnull DetectionLocation detectionLocation) {
        return switch (rawName.toUpperCase().trim()) {
            // RSA secret value encapsulation (RSASVE, NIST SP 800-56B)
            case "RSA" ->
                    Optional.of(
                            new RSA(KeyEncapsulationMechanism.class, new RSA(detectionLocation)));
            // DHKEM (RFC 9180) over the curve of the key
            case "EC" -> Optional.of(dhkem(new ECDH(detectionLocation), detectionLocation));
            case "X25519" -> Optional.of(dhkem(new X25519(detectionLocation), detectionLocation));
            case "X448" -> Optional.of(dhkem(new X448(detectionLocation), detectionLocation));
            default -> byName(rawName, detectionLocation);
        };
    }

    /**
     * An HPKE suite {@code "<KEM>,<KDF>,<AEAD>"} as resolved by {@link
     * com.ibm.plugin.rules.detection.openssl.keyagreement.OpenSSLHpkeSuiteFactory}. The export-only
     * AEAD has no cipher.
     */
    @Nonnull
    private Optional<INode> hpkeBySuite(
            @Nonnull String suite, @Nonnull DetectionLocation detectionLocation) {
        final String[] parts = suite.split(",");
        if (parts.length != 3) {
            return Optional.empty();
        }
        final Optional<INode> kem =
                switch (parts[0]) {
                    case "P-256" -> Optional.of(dhkemOverCurve("secp256r1", detectionLocation));
                    case "P-384" -> Optional.of(dhkemOverCurve("secp384r1", detectionLocation));
                    case "P-521" -> Optional.of(dhkemOverCurve("secp521r1", detectionLocation));
                    case "X25519" ->
                            Optional.of(dhkem(new X25519(detectionLocation), detectionLocation));
                    case "X448" ->
                            Optional.of(dhkem(new X448(detectionLocation), detectionLocation));
                    default -> Optional.empty();
                };
        final Optional<INode> kdf =
                switch (parts[1]) {
                    case "HKDF-SHA256" -> Optional.of(new HKDF(new SHA2(256, detectionLocation)));
                    case "HKDF-SHA384" -> Optional.of(new HKDF(new SHA2(384, detectionLocation)));
                    case "HKDF-SHA512" -> Optional.of(new HKDF(new SHA2(512, detectionLocation)));
                    default -> Optional.empty();
                };
        final Optional<INode> aead =
                switch (parts[2]) {
                    case "AES-128-GCM" ->
                            Optional.of(
                                    new AES(128, new GCM(detectionLocation), detectionLocation));
                    case "AES-256-GCM" ->
                            Optional.of(
                                    new AES(256, new GCM(detectionLocation), detectionLocation));
                    case "CHACHA20-POLY1305" ->
                            Optional.of(new ChaCha20Poly1305(detectionLocation));
                    default -> Optional.empty();
                };
        if (kem.isEmpty() || kdf.isEmpty()) {
            return Optional.empty();
        }
        final Algorithm hpke = new Algorithm("HPKE", PublicKeyEncryption.class, detectionLocation);
        hpke.put(kem.get());
        hpke.put(kdf.get());
        aead.ifPresent(hpke::put);
        return Optional.of(hpke);
    }

    @Nonnull
    private static Algorithm dhkemOverCurve(
            @Nonnull String curve, @Nonnull DetectionLocation detectionLocation) {
        return dhkem(new ECDH(new EllipticCurve(curve, detectionLocation)), detectionLocation);
    }

    @Nonnull
    private static Algorithm dhkem(
            @Nonnull INode diffieHellman, @Nonnull DetectionLocation detectionLocation) {
        final Algorithm dhkem =
                new Algorithm("DHKEM", KeyEncapsulationMechanism.class, detectionLocation);
        dhkem.put(diffieHellman);
        return dhkem;
    }

    @Nonnull
    private Optional<INode> byName(
            @Nonnull String rawName, @Nonnull DetectionLocation detectionLocation) {
        String algorithmName = rawName.toUpperCase().trim();

        // DH (Diffie-Hellman)
        if (algorithmName.equals("DH")) {
            return Optional.of(new DH(KeyAgreement.class, detectionLocation));
        }
        if (algorithmName.equals("DH-2048")) {
            return Optional.of(new DH(KeyAgreement.class, detectionLocation));
        }
        if (algorithmName.equals("DH-3072")) {
            return Optional.of(new DH(KeyAgreement.class, detectionLocation));
        }
        if (algorithmName.equals("DH-4096")) {
            return Optional.of(new DH(KeyAgreement.class, detectionLocation));
        }

        // ECDH (Elliptic Curve Diffie-Hellman)
        if (algorithmName.equals("ECDH")
                || algorithmName.equals("ECDH-P256")
                || algorithmName.equals("ECDH-P384")
                || algorithmName.equals("ECDH-P521")
                || algorithmName.equals("ECDH-SECP256K1")) {
            return Optional.of(new ECDH(detectionLocation));
        }

        // X25519 and X448
        if (algorithmName.equals("X25519")) {
            return Optional.of(new X25519(detectionLocation));
        }
        if (algorithmName.equals("X448")) {
            return Optional.of(new X448(detectionLocation));
        }

        // ML-KEM (Kyber) - Post-Quantum Key Encapsulation Mechanism
        if (algorithmName.equals("ML-KEM-512")) {
            return Optional.of(new MLKEM(512, detectionLocation));
        }
        if (algorithmName.equals("ML-KEM-768")) {
            return Optional.of(new MLKEM(768, detectionLocation));
        }
        if (algorithmName.equals("ML-KEM-1024")) {
            return Optional.of(new MLKEM(1024, detectionLocation));
        }

        // Hybrid Post-Quantum KEMs (PQC + Classical)
        if (algorithmName.equals("X25519MLKEM768")) {
            return Optional.of(new X25519MLKEM768(detectionLocation));
        }
        if (algorithmName.equals("X448MLKEM1024")) {
            return Optional.of(new X448MLKEM1024(detectionLocation));
        }
        if (algorithmName.equals("SECP256R1MLKEM768")) {
            return Optional.of(new SecP256r1MLKEM768(detectionLocation));
        }
        if (algorithmName.equals("SECP384R1MLKEM1024")) {
            return Optional.of(new SecP384r1MLKEM1024(detectionLocation));
        }

        // SM2 Key Exchange
        if (algorithmName.equals("SM2")) {
            return Optional.of(new SM2(detectionLocation));
        }

        return Optional.empty();
    }
}
