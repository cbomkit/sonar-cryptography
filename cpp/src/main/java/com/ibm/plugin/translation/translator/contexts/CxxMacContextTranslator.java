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
import com.ibm.mapper.model.Mac;
import com.ibm.mapper.model.algorithms.AES;
import com.ibm.mapper.model.algorithms.Aria;
import com.ibm.mapper.model.algorithms.CMAC;
import com.ibm.mapper.model.algorithms.Camellia;
import com.ibm.mapper.model.algorithms.DESede;
import com.ibm.mapper.model.algorithms.HMAC;
import com.ibm.mapper.model.algorithms.KMAC;
import com.ibm.mapper.model.algorithms.MD5;
import com.ibm.mapper.model.algorithms.Poly1305;
import com.ibm.mapper.model.algorithms.RIPEMD;
import com.ibm.mapper.model.algorithms.SHA;
import com.ibm.mapper.model.algorithms.SHA2;
import com.ibm.mapper.model.algorithms.SHA3;
import com.ibm.mapper.model.algorithms.SM3;
import com.ibm.mapper.model.algorithms.SM4;
import com.ibm.mapper.model.algorithms.SipHash;
import com.ibm.mapper.model.algorithms.blake.BLAKE2b;
import com.ibm.mapper.model.algorithms.blake.BLAKE2s;
import com.ibm.mapper.utils.DetectionLocation;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.Optional;
import javax.annotation.Nonnull;

/**
 * Translator for C++ MAC detection contexts.
 *
 * <p>This translator handles the translation of MAC-related detection values to the mapper model
 * nodes. Supports HMAC, CMAC, GMAC, Poly1305, SipHash, KMAC, and BLAKE2 MAC variants.
 */
public final class CxxMacContextTranslator implements IContextTranslation<AstNode> {

    @Override
    public @Nonnull Optional<INode> translate(
            @Nonnull IBundle bundleIdentifier,
            @Nonnull IValue<AstNode> value,
            @Nonnull IDetectionContext detectionContext,
            @Nonnull DetectionLocation detectionLocation) {

        if (value instanceof ValueAction<AstNode>
                || value instanceof com.ibm.engine.model.Algorithm<AstNode>) {
            return switch (value.asString().toUpperCase().trim()) {
                // Names accepted by EVP_MAC_fetch. The digest of an HMAC and the cipher of a CMAC
                // or GMAC are set through OSSL_PARAMs of the context and attached as children.
                case "HMAC" -> Optional.of(new HMAC(detectionLocation));
                case "CMAC" -> Optional.of(new CMAC(detectionLocation));
                case "GMAC" -> Optional.of(new Algorithm("GMAC", Mac.class, detectionLocation));
                case "KMAC-128", "KMAC128" -> Optional.of(new KMAC(128, detectionLocation));
                case "KMAC-256", "KMAC256" -> Optional.of(new KMAC(256, detectionLocation));
                case "SIPHASH" -> Optional.of(new SipHash(detectionLocation));

                // HMAC variants
                case "HMAC-MD5" -> Optional.of(new HMAC(new MD5(detectionLocation)));
                case "HMAC-SHA1" -> Optional.of(new HMAC(new SHA(detectionLocation)));
                case "HMAC-SHA224" -> Optional.of(new HMAC(new SHA2(224, detectionLocation)));
                case "HMAC-SHA256" -> Optional.of(new HMAC(new SHA2(256, detectionLocation)));
                case "HMAC-SHA384" -> Optional.of(new HMAC(new SHA2(384, detectionLocation)));
                case "HMAC-SHA512" -> Optional.of(new HMAC(new SHA2(512, detectionLocation)));
                // SHA-512/224 and SHA-512/256 are truncated variants of SHA-512
                case "HMAC-SHA512/224" -> Optional.of(new HMAC(new SHA2(224, detectionLocation)));
                case "HMAC-SHA512/256" -> Optional.of(new HMAC(new SHA2(256, detectionLocation)));
                case "HMAC-SHA3-224" -> Optional.of(new HMAC(new SHA3(224, detectionLocation)));
                case "HMAC-SHA3-256" -> Optional.of(new HMAC(new SHA3(256, detectionLocation)));
                case "HMAC-SHA3-384" -> Optional.of(new HMAC(new SHA3(384, detectionLocation)));
                case "HMAC-SHA3-512" -> Optional.of(new HMAC(new SHA3(512, detectionLocation)));
                case "HMAC-RIPEMD160" -> Optional.of(new HMAC(new RIPEMD(160, detectionLocation)));
                case "HMAC-BLAKE2B" ->
                        Optional.of(new HMAC(new BLAKE2b(512, false, detectionLocation)));
                case "HMAC-BLAKE2S" ->
                        Optional.of(new HMAC(new BLAKE2s(256, false, detectionLocation)));
                case "HMAC-SM3" -> Optional.of(new HMAC(new SM3(detectionLocation)));

                // CMAC variants
                case "CMAC-AES-128" -> Optional.of(new CMAC(new AES(128, detectionLocation)));
                case "CMAC-AES-192" -> Optional.of(new CMAC(new AES(192, detectionLocation)));
                case "CMAC-AES-256" -> Optional.of(new CMAC(new AES(256, detectionLocation)));
                case "CMAC-3DES" -> Optional.of(new CMAC(new DESede(168, detectionLocation)));
                case "CMAC-CAMELLIA-128" ->
                        Optional.of(new CMAC(new Camellia(128, detectionLocation)));
                case "CMAC-CAMELLIA-192" ->
                        Optional.of(new CMAC(new Camellia(192, detectionLocation)));
                case "CMAC-CAMELLIA-256" ->
                        Optional.of(new CMAC(new Camellia(256, detectionLocation)));
                case "CMAC-ARIA-128" -> Optional.of(new CMAC(new Aria(128, detectionLocation)));
                case "CMAC-ARIA-192" -> Optional.of(new CMAC(new Aria(192, detectionLocation)));
                case "CMAC-ARIA-256" -> Optional.of(new CMAC(new Aria(256, detectionLocation)));
                case "CMAC-SM4" -> Optional.of(new CMAC(new SM4(detectionLocation)));

                // GMAC variants (Galois MAC — AES-GCM authentication-only mode)
                case "GMAC-AES-128" -> {
                    Algorithm gmac = new Algorithm("GMAC", Mac.class, detectionLocation);
                    gmac.put(new AES(128, detectionLocation));
                    yield Optional.of(gmac);
                }
                case "GMAC-AES-192" -> {
                    Algorithm gmac = new Algorithm("GMAC", Mac.class, detectionLocation);
                    gmac.put(new AES(192, detectionLocation));
                    yield Optional.of(gmac);
                }
                case "GMAC-AES-256" -> {
                    Algorithm gmac = new Algorithm("GMAC", Mac.class, detectionLocation);
                    gmac.put(new AES(256, detectionLocation));
                    yield Optional.of(gmac);
                }

                // Poly1305
                case "POLY1305" ->
                        Optional.of(new Poly1305(Mac.class, new Poly1305(detectionLocation)));

                // BLAKE2 MAC
                case "BLAKE2BMAC" ->
                        Optional.of(
                                new BLAKE2b(Mac.class, new BLAKE2b(512, false, detectionLocation)));
                case "BLAKE2SMAC" ->
                        Optional.of(
                                new BLAKE2s(Mac.class, new BLAKE2s(256, false, detectionLocation)));

                default -> Optional.empty();
            };
        }

        return Optional.empty();
    }
}
