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
import com.ibm.mapper.model.PseudorandomNumberGenerator;
import com.ibm.mapper.model.algorithms.AES;
import com.ibm.mapper.model.algorithms.SHA;
import com.ibm.mapper.model.algorithms.SHA2;
import com.ibm.mapper.utils.DetectionLocation;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.Optional;
import javax.annotation.Nonnull;

/**
 * Translator for C++ PRNG (Pseudo-Random Number Generator) detection contexts.
 *
 * <p>This translator handles the translation of PRNG-related detection values (RAND, DRBG variants)
 * to the mapper model nodes.
 */
public final class CxxPRNGContextTranslator implements IContextTranslation<AstNode> {

    @Override
    public @Nonnull Optional<INode> translate(
            @Nonnull IBundle bundleIdentifier,
            @Nonnull IValue<AstNode> value,
            @Nonnull IDetectionContext detectionContext,
            @Nonnull DetectionLocation detectionLocation) {

        if (value instanceof ValueAction<AstNode>
                || value instanceof com.ibm.engine.model.Algorithm<AstNode>) {
            return switch (value.asString().toUpperCase().trim()) {
                // Basic RAND operations
                case "RAND" ->
                        Optional.of(
                                new Algorithm(
                                        "RAND",
                                        PseudorandomNumberGenerator.class,
                                        detectionLocation));
                case "RAND-PSEUDO" ->
                        Optional.of(
                                new Algorithm(
                                        "RAND-PSEUDO",
                                        PseudorandomNumberGenerator.class,
                                        detectionLocation));

                // DRBG family name only (RAND_set_DRBG_type's drbg argument, without a
                // separately-captured cipher/digest suffix)
                case "CTR-DRBG" ->
                        Optional.of(
                                new Algorithm(
                                        "CTR-DRBG",
                                        PseudorandomNumberGenerator.class,
                                        detectionLocation));
                case "HASH-DRBG" ->
                        Optional.of(
                                new Algorithm(
                                        "HASH-DRBG",
                                        PseudorandomNumberGenerator.class,
                                        detectionLocation));
                case "HMAC-DRBG" ->
                        Optional.of(
                                new Algorithm(
                                        "HMAC-DRBG",
                                        PseudorandomNumberGenerator.class,
                                        detectionLocation));

                // CTR-DRBG (Counter mode DRBG) - AES-based
                case "CTR-DRBG-AES128" ->
                        Optional.of(
                                new AES(
                                        PseudorandomNumberGenerator.class,
                                        new AES(128, detectionLocation)));
                case "CTR-DRBG-AES192" ->
                        Optional.of(
                                new AES(
                                        PseudorandomNumberGenerator.class,
                                        new AES(192, detectionLocation)));
                case "CTR-DRBG-AES256" ->
                        Optional.of(
                                new AES(
                                        PseudorandomNumberGenerator.class,
                                        new AES(256, detectionLocation)));

                // HASH-DRBG (Hash-based DRBG)
                case "HASH-DRBG-SHA1" ->
                        Optional.of(
                                new SHA(
                                        PseudorandomNumberGenerator.class,
                                        new SHA(detectionLocation)));
                case "HASH-DRBG-SHA256" ->
                        Optional.of(
                                new SHA2(
                                        PseudorandomNumberGenerator.class,
                                        new SHA2(256, detectionLocation)));
                case "HASH-DRBG-SHA384" ->
                        Optional.of(
                                new SHA2(
                                        PseudorandomNumberGenerator.class,
                                        new SHA2(384, detectionLocation)));
                case "HASH-DRBG-SHA512" ->
                        Optional.of(
                                new SHA2(
                                        PseudorandomNumberGenerator.class,
                                        new SHA2(512, detectionLocation)));

                // HMAC-DRBG (HMAC-based DRBG) - use same hash-based approach
                case "HMAC-DRBG-SHA1" ->
                        Optional.of(
                                new SHA(
                                        PseudorandomNumberGenerator.class,
                                        new SHA(detectionLocation)));
                case "HMAC-DRBG-SHA256" ->
                        Optional.of(
                                new SHA2(
                                        PseudorandomNumberGenerator.class,
                                        new SHA2(256, detectionLocation)));
                case "HMAC-DRBG-SHA384" ->
                        Optional.of(
                                new SHA2(
                                        PseudorandomNumberGenerator.class,
                                        new SHA2(384, detectionLocation)));
                case "HMAC-DRBG-SHA512" ->
                        Optional.of(
                                new SHA2(
                                        PseudorandomNumberGenerator.class,
                                        new SHA2(512, detectionLocation)));

                // Entropy sources (OpenSSL provider-based)
                case "SEED-SRC" ->
                        Optional.of(
                                new Algorithm(
                                        "SEED-SRC",
                                        PseudorandomNumberGenerator.class,
                                        detectionLocation));
                case "JITTER" ->
                        Optional.of(
                                new Algorithm(
                                        "JITTER",
                                        PseudorandomNumberGenerator.class,
                                        detectionLocation));
                case "TEST-RAND" ->
                        Optional.of(
                                new Algorithm(
                                        "TEST-RAND",
                                        PseudorandomNumberGenerator.class,
                                        detectionLocation));

                // Entropy seeding operations (not distinct algorithms — yield empty)
                case "RAND-SEED", "RAND-ADD", "RAND-POLL" -> Optional.empty();

                default -> Optional.empty();
            };
        }

        return Optional.empty();
    }
}
