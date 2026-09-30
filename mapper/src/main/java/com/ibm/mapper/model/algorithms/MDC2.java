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
import com.ibm.mapper.model.BlockSize;
import com.ibm.mapper.model.DigestSize;
import com.ibm.mapper.model.IPrimitive;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.utils.DetectionLocation;
import javax.annotation.Nonnull;

/**
 *
 *
 * <h2>{@value #NAME}</h2>
 *
 * <p>Modification Detection Code 2: a 128-bit hash function built on the DES block cipher.
 *
 * <h3>Specification</h3>
 *
 * <ul>
 *   <li>ISO/IEC 10118-2
 *   <li>https://en.wikipedia.org/wiki/MDC-2
 * </ul>
 *
 * <h3>Other Names and Related Standards</h3>
 *
 * <ul>
 *   <li>MDC-2, Meyer-Schilling hash
 * </ul>
 */
public final class MDC2 extends Algorithm implements MessageDigest {

    private static final String NAME = "MDC2";

    public MDC2(@Nonnull DetectionLocation detectionLocation) {
        super(NAME, MessageDigest.class, detectionLocation);
        this.put(BlockSize.ofDefault(64, detectionLocation));
        this.put(new DigestSize(128, detectionLocation));
    }

    private MDC2(@Nonnull MDC2 algorithm) {
        super(algorithm);
    }

    @Nonnull
    @Override
    protected MDC2 copy() {
        return new MDC2(this);
    }

    public MDC2(@Nonnull final Class<? extends IPrimitive> asKind, @Nonnull MDC2 mdc2) {
        super(mdc2, asKind);
    }

    @Nonnull
    @Override
    public MDC2 asKind(@Nonnull Class<? extends IPrimitive> kind) {
        return new MDC2(kind, this);
    }
}
