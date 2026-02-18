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
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.algorithms.MD2;
import com.ibm.mapper.model.algorithms.MD4;
import com.ibm.mapper.model.algorithms.MD5;
import com.ibm.mapper.model.algorithms.RIPEMD;
import com.ibm.mapper.model.algorithms.SHA;
import com.ibm.mapper.model.algorithms.SHA2;
import com.ibm.mapper.model.algorithms.SHA3;
import com.ibm.mapper.model.algorithms.SM3;
import com.ibm.mapper.model.algorithms.Whirlpool;
import com.ibm.mapper.model.algorithms.blake.BLAKE2b;
import com.ibm.mapper.model.algorithms.blake.BLAKE2s;
import com.ibm.mapper.model.algorithms.shake.SHAKE;
import com.ibm.mapper.utils.DetectionLocation;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.Optional;
import javax.annotation.Nonnull;

public final class CxxDigestContextTranslator implements IContextTranslation<AstNode> {

    @Override
    public @Nonnull Optional<INode> translate(
            @Nonnull IBundle bundleIdentifier,
            @Nonnull IValue<AstNode> value,
            @Nonnull IDetectionContext detectionContext,
            @Nonnull DetectionLocation detectionLocation) {

        if (value instanceof ValueAction<AstNode>) {
            return switch (value.asString().toUpperCase().trim()) {
                // MD Family
                case "MD2" -> Optional.of(new MD2(detectionLocation));
                case "MD4" -> Optional.of(new MD4(detectionLocation));
                case "MD5" -> Optional.of(new MD5(detectionLocation));
                // MDC2 (ISO/IEC 10118-2) is a hash function built on DES, not MD5
                case "MDC2" ->
                        Optional.of(new Algorithm("MDC2", MessageDigest.class, detectionLocation));

                // SHA-1
                case "SHA-1" -> Optional.of(new SHA(detectionLocation));

                // SHA-2
                case "SHA-224" -> Optional.of(new SHA2(224, detectionLocation));
                case "SHA-256" -> Optional.of(new SHA2(256, detectionLocation));
                case "SHA-384" -> Optional.of(new SHA2(384, detectionLocation));
                case "SHA-512" -> Optional.of(new SHA2(512, detectionLocation));
                case "SHA-512/224" ->
                        Optional.of(
                                new SHA2(224, new SHA2(512, detectionLocation), detectionLocation));
                case "SHA-512/256" ->
                        Optional.of(
                                new SHA2(256, new SHA2(512, detectionLocation), detectionLocation));

                // SHA-3
                case "SHA3-224" -> Optional.of(new SHA3(224, detectionLocation));
                case "SHA3-256" -> Optional.of(new SHA3(256, detectionLocation));
                case "SHA3-384" -> Optional.of(new SHA3(384, detectionLocation));
                case "SHA3-512" -> Optional.of(new SHA3(512, detectionLocation));

                // SHAKE (Extendable-Output Functions)
                case "SHAKE128" -> Optional.of(new SHAKE(128, detectionLocation));
                case "SHAKE256" -> Optional.of(new SHAKE(256, detectionLocation));

                // RIPEMD
                case "RIPEMD160" -> Optional.of(new RIPEMD(160, detectionLocation));

                // Whirlpool
                case "WHIRLPOOL" -> Optional.of(new Whirlpool(detectionLocation));

                // BLAKE2
                case "BLAKE2B-512" -> Optional.of(new BLAKE2b(512, false, detectionLocation));
                case "BLAKE2S-256" -> Optional.of(new BLAKE2s(256, false, detectionLocation));

                // SM3
                case "SM3" -> Optional.of(new SM3(detectionLocation));

                // Combined/Special digests
                case "MD5-SHA1" -> {
                    // Combined MD5+SHA1 for TLS 1.0 (concatenated output: 128-bit MD5 + 160-bit
                    // SHA-1)
                    yield Optional.of(
                            new MD5(detectionLocation)); // Primary algorithm, may need composite
                    // handling
                }
                case "NULL" -> Optional.empty(); // NULL digest - no actual hashing

                default -> Optional.empty();
            };
        }

        return Optional.empty();
    }
}
