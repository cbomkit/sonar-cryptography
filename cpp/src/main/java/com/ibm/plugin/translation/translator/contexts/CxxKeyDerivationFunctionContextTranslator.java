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
import com.ibm.engine.model.context.IDetectionContext;
import com.ibm.engine.rule.IBundle;
import com.ibm.mapper.IContextTranslation;
import com.ibm.mapper.model.Algorithm;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.KeyDerivationFunction;
import com.ibm.mapper.model.PasswordBasedKeyDerivationFunction;
import com.ibm.mapper.model.algorithms.AES;
import com.ibm.mapper.model.algorithms.ANSIX942;
import com.ibm.mapper.model.algorithms.ANSIX963;
import com.ibm.mapper.model.algorithms.CMAC;
import com.ibm.mapper.model.algorithms.ConcatenationKDF;
import com.ibm.mapper.model.algorithms.HKDF;
import com.ibm.mapper.model.algorithms.HMAC;
import com.ibm.mapper.model.algorithms.KDFCounter;
import com.ibm.mapper.model.algorithms.MD5;
import com.ibm.mapper.model.algorithms.PBKDF1;
import com.ibm.mapper.model.algorithms.PBKDF2;
import com.ibm.mapper.model.algorithms.SHA;
import com.ibm.mapper.model.algorithms.SHA2;
import com.ibm.mapper.model.algorithms.SHA3;
import com.ibm.mapper.model.algorithms.SSHKDF;
import com.ibm.mapper.model.algorithms.Scrypt;
import com.ibm.mapper.model.algorithms.TLSPRF;
import com.ibm.mapper.utils.DetectionLocation;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.Optional;
import javax.annotation.Nonnull;

public final class CxxKeyDerivationFunctionContextTranslator
        implements IContextTranslation<AstNode> {

    @Override
    public @Nonnull Optional<INode> translate(
            @Nonnull IBundle bundleIdentifier,
            @Nonnull IValue<AstNode> value,
            @Nonnull IDetectionContext detectionContext,
            @Nonnull DetectionLocation detectionLocation) {

        if (value instanceof ValueAction<AstNode>) {
            return switch (value.asString().toUpperCase().trim()) {
                // PBKDF2
                case "PBKDF2-HMAC-SHA1" -> Optional.of(new PBKDF2(new SHA(detectionLocation)));
                case "PBKDF2-HMAC-SHA256" ->
                        Optional.of(new PBKDF2(new SHA2(256, detectionLocation)));
                case "PBKDF2-HMAC-SHA384" ->
                        Optional.of(new PBKDF2(new SHA2(384, detectionLocation)));
                case "PBKDF2-HMAC-SHA512" ->
                        Optional.of(new PBKDF2(new SHA2(512, detectionLocation)));
                case "PBKDF2-HMAC-SHA3-256" ->
                        Optional.of(new PBKDF2(new SHA3(256, detectionLocation)));
                case "PBKDF2-HMAC-SHA3-512" ->
                        Optional.of(new PBKDF2(new SHA3(512, detectionLocation)));
                case "PBKDF2-HMAC-SM3", "PBKDF2-HMAC-MD5" ->
                        Optional.of(new PBKDF2(detectionLocation));

                // HKDF
                case "HKDF-SHA1" -> Optional.of(new HKDF(new SHA(detectionLocation)));
                case "HKDF-SHA256" -> Optional.of(new HKDF(new SHA2(256, detectionLocation)));
                case "HKDF-SHA384" -> Optional.of(new HKDF(new SHA2(384, detectionLocation)));
                case "HKDF-SHA512" -> Optional.of(new HKDF(new SHA2(512, detectionLocation)));
                case "HKDF-SHA3-256" -> Optional.of(new HKDF(new SHA3(256, detectionLocation)));

                // Scrypt
                case "SCRYPT" -> Optional.of(new Scrypt(detectionLocation));

                // TLS PRF
                case "TLS1-PRF-MD5-SHA1" -> Optional.of(new TLSPRF(detectionLocation));
                case "TLS1-PRF-SHA256" -> Optional.of(new TLSPRF(new SHA2(256, detectionLocation)));
                case "TLS1-PRF-SHA384" -> Optional.of(new TLSPRF(new SHA2(384, detectionLocation)));
                case "TLS1-PRF-SHA512" -> Optional.of(new TLSPRF(new SHA2(512, detectionLocation)));

                // TLS 1.3 KDF
                case "TLS13-KDF-SHA256" -> Optional.of(new HKDF(new SHA2(256, detectionLocation)));
                case "TLS13-KDF-SHA384" -> Optional.of(new HKDF(new SHA2(384, detectionLocation)));
                case "TLS13-KDF-SHA512" -> Optional.of(new HKDF(new SHA2(512, detectionLocation)));

                // X963KDF
                case "X963KDF-SHA1" -> Optional.of(new ANSIX963(new SHA(detectionLocation)));
                case "X963KDF-SHA224" ->
                        Optional.of(new ANSIX963(new SHA2(224, detectionLocation)));
                case "X963KDF-SHA256" ->
                        Optional.of(new ANSIX963(new SHA2(256, detectionLocation)));
                case "X963KDF-SHA384" ->
                        Optional.of(new ANSIX963(new SHA2(384, detectionLocation)));
                case "X963KDF-SHA512" ->
                        Optional.of(new ANSIX963(new SHA2(512, detectionLocation)));

                // KBKDF (SP 800-108 Key-Based KDF) — counter mode with HMAC or CMAC
                case "KBKDF-HMAC-SHA1" ->
                        Optional.of(new KDFCounter(new HMAC(new SHA(detectionLocation))));
                case "KBKDF-HMAC-SHA256" ->
                        Optional.of(new KDFCounter(new HMAC(new SHA2(256, detectionLocation))));
                case "KBKDF-HMAC-SHA384" ->
                        Optional.of(new KDFCounter(new HMAC(new SHA2(384, detectionLocation))));
                case "KBKDF-HMAC-SHA512" ->
                        Optional.of(new KDFCounter(new HMAC(new SHA2(512, detectionLocation))));
                case "KBKDF-CMAC-AES128" ->
                        Optional.of(new KDFCounter(new CMAC(new AES(128, detectionLocation))));
                case "KBKDF-CMAC-AES256" ->
                        Optional.of(new KDFCounter(new CMAC(new AES(256, detectionLocation))));

                // X942KDF (ANSI X9.42 Key Derivation)
                case "X942KDF-ASN1", "X942KDF-CONCAT" ->
                        Optional.of(new ANSIX942(detectionLocation));

                // SSKDF (Single-step KDF / ConcatenationKDF)
                case "SSKDF", "SSKDF-SHA256", "SSKDF-SHA512" ->
                        Optional.of(new ConcatenationKDF(detectionLocation));

                // SSHKDF
                case "SSHKDF-SHA1" -> Optional.of(new SSHKDF(new SHA(detectionLocation)));
                case "SSHKDF-SHA256" -> Optional.of(new SSHKDF(new SHA2(256, detectionLocation)));
                case "SSHKDF-SHA512" -> Optional.of(new SSHKDF(new SHA2(512, detectionLocation)));

                // KRB5KDF (Kerberos Key Derivation Function)
                case "KRB5KDF" ->
                        Optional.of(
                                new Algorithm(
                                        "KRB5KDF", KeyDerivationFunction.class, detectionLocation));

                // Argon2 (password-based KDF / memory-hard)
                case "ARGON2D" ->
                        Optional.of(
                                new Algorithm(
                                        "Argon2d",
                                        PasswordBasedKeyDerivationFunction.class,
                                        detectionLocation));
                case "ARGON2I" ->
                        Optional.of(
                                new Algorithm(
                                        "Argon2i",
                                        PasswordBasedKeyDerivationFunction.class,
                                        detectionLocation));
                case "ARGON2ID" ->
                        Optional.of(
                                new Algorithm(
                                        "Argon2id",
                                        PasswordBasedKeyDerivationFunction.class,
                                        detectionLocation));

                // PKCS12KDF (PKCS#12 password-based key derivation)
                case "PKCS12KDF" ->
                        Optional.of(
                                new Algorithm(
                                        "PKCS12KDF",
                                        PasswordBasedKeyDerivationFunction.class,
                                        detectionLocation));

                // PVKKDF (Microsoft PVK file key derivation)
                case "PVKKDF" ->
                        Optional.of(
                                new Algorithm(
                                        "PVKKDF",
                                        PasswordBasedKeyDerivationFunction.class,
                                        detectionLocation));

                // PBKDF1 (legacy, PKCS#5 v1.5)
                case "PBKDF1-MD5" -> Optional.of(new PBKDF1(new MD5(detectionLocation)));
                case "PBKDF1-SHA1" -> Optional.of(new PBKDF1(new SHA(detectionLocation)));

                // PBKDF2-HMAC (bare, without explicit digest)
                case "PBKDF2-HMAC" -> Optional.of(new PBKDF2(detectionLocation));

                // HMAC-DRBG-KDF
                case "HMAC-DRBG-KDF" ->
                        Optional.of(
                                new Algorithm(
                                        "HMAC-DRBG-KDF",
                                        KeyDerivationFunction.class,
                                        detectionLocation));

                default -> Optional.empty();
            };
        }

        return Optional.empty();
    }
}
