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
import com.ibm.mapper.model.BlockCipher;
import com.ibm.mapper.model.IAlgorithm;
import com.ibm.mapper.model.IPrimitive;
import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.model.PseudorandomNumberGenerator;
import com.ibm.mapper.utils.DetectionLocation;
import javax.annotation.Nonnull;

/**
 *
 *
 * <h2>{@value #NAME}</h2>
 *
 * <p>Deterministic random bit generator built on a block cipher in counter mode, which is a child
 * of this node.
 *
 * <h3>Specification</h3>
 *
 * <ul>
 *   <li>See 10.2 of https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-90Ar1.pdf
 *   <li>https://cyclonedx.org/schema/cryptography-defs.json (pattern:
 *       CTR_DRBG[-{cipherAlgorithm}][-{keyLength}])
 * </ul>
 *
 * <h3>Other Names and Related Standards</h3>
 *
 * <ul>
 *   <li>NIST SP 800-90A
 * </ul>
 */
public final class CTRDRBG extends Algorithm implements PseudorandomNumberGenerator {

    private static final String NAME = "CTR_DRBG";

    public CTRDRBG(@Nonnull DetectionLocation detectionLocation) {
        super(NAME, PseudorandomNumberGenerator.class, detectionLocation);
    }

    @Override
    public @Nonnull String asString() {
        return this.hasChildOfType(BlockCipher.class)
                .map(
                        cipher -> {
                            String withCipher = this.name + "-" + ((IAlgorithm) cipher).getName();
                            return cipher.hasChildOfType(KeyLength.class)
                                    .map(keyLength -> withCipher + "-" + keyLength.asString())
                                    .orElse(withCipher);
                        })
                .orElse(this.name);
    }

    private CTRDRBG(@Nonnull CTRDRBG algorithm) {
        super(algorithm);
    }

    @Nonnull
    @Override
    protected CTRDRBG copy() {
        return new CTRDRBG(this);
    }

    public CTRDRBG(@Nonnull final Class<? extends IPrimitive> asKind, @Nonnull CTRDRBG ctrdrbg) {
        super(ctrdrbg, asKind);
    }

    @Nonnull
    @Override
    public CTRDRBG asKind(@Nonnull Class<? extends IPrimitive> kind) {
        return new CTRDRBG(kind, this);
    }
}
