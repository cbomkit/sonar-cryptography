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
package com.ibm.mapper.mapper.openssl;

import com.ibm.mapper.mapper.IMapper;
import com.ibm.mapper.model.Algorithm;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.PseudorandomNumberGenerator;
import com.ibm.mapper.model.algorithms.CTRDRBG;
import com.ibm.mapper.model.algorithms.HMACDRBG;
import com.ibm.mapper.model.algorithms.HashDRBG;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

/**
 * Maps the OpenSSL random generator names (the names accepted by {@code EVP_RAND_fetch} and {@code
 * RAND_set_DRBG_type}, and the names the random detection rules give the {@code RAND_*} functions)
 * to the model.
 */
public class OpenSslPRNGMapper implements IMapper {

    @Nonnull
    @Override
    public Optional<? extends INode> parse(
            @Nullable final String str, @Nonnull DetectionLocation detectionLocation) {
        if (str == null) {
            return Optional.empty();
        }
        return switch (str.toUpperCase().trim()) {
            // Basic RAND operations
            case "RAND" ->
                    Optional.of(
                            new Algorithm(
                                    "RAND", PseudorandomNumberGenerator.class, detectionLocation));
            case "RAND-PSEUDO" ->
                    Optional.of(
                            new Algorithm(
                                    "RAND-PSEUDO",
                                    PseudorandomNumberGenerator.class,
                                    detectionLocation));

            // DRBG names accepted by EVP_RAND_fetch and RAND_set_DRBG_type (NIST SP 800-90A).
            // The cipher or digest of the DRBG is attached to the node as a child.
            case "CTR-DRBG" -> Optional.of(new CTRDRBG(detectionLocation));
            case "HASH-DRBG" -> Optional.of(new HashDRBG(detectionLocation));
            case "HMAC-DRBG" -> Optional.of(new HMACDRBG(detectionLocation));

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
}
