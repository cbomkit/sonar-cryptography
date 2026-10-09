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
package com.ibm.mapper.model.algorithms;

import com.ibm.mapper.model.Algorithm;
import com.ibm.mapper.model.IAlgorithm;
import com.ibm.mapper.model.IPrimitive;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.PseudorandomNumberGenerator;
import com.ibm.mapper.utils.DetectionLocation;
import javax.annotation.Nonnull;

/**
 *
 *
 * <h2>{@value #NAME}</h2>
 *
 * <p>Deterministic random bit generator built on a hash function, which is a child of this node.
 *
 * <h3>Specification</h3>
 *
 * <ul>
 *   <li>See 10.1.1 of https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-90Ar1.pdf
 *   <li>https://cyclonedx.org/schema/cryptography-defs.json (pattern: Hash_DRBG[-{hashAlgorithm}])
 * </ul>
 *
 * <h3>Other Names and Related Standards</h3>
 *
 * <ul>
 *   <li>NIST SP 800-90A
 * </ul>
 */
public final class HashDRBG extends Algorithm implements PseudorandomNumberGenerator {

    private static final String NAME = "Hash_DRBG";

    public HashDRBG(@Nonnull DetectionLocation detectionLocation) {
        super(NAME, PseudorandomNumberGenerator.class, detectionLocation);
    }

    @Override
    public @Nonnull String asString() {
        return this.hasChildOfType(MessageDigest.class)
                .map(algorithm -> this.name + "-" + ((IAlgorithm) algorithm).getName())
                .orElse(this.name);
    }

    private HashDRBG(@Nonnull HashDRBG algorithm) {
        super(algorithm);
    }

    @Nonnull
    @Override
    protected HashDRBG copy() {
        return new HashDRBG(this);
    }

    public HashDRBG(@Nonnull final Class<? extends IPrimitive> asKind, @Nonnull HashDRBG hashDRBG) {
        super(hashDRBG, asKind);
    }

    @Nonnull
    @Override
    public HashDRBG asKind(@Nonnull Class<? extends IPrimitive> kind) {
        return new HashDRBG(kind, this);
    }
}
