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

                // DRBG names accepted by EVP_RAND_fetch and RAND_set_DRBG_type. The cipher or
                // digest of the DRBG is attached to the node as a child.
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
