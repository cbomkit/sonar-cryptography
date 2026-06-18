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
package com.ibm.mapper.model.algorithms.blake;

import com.ibm.mapper.model.Algorithm;
import com.ibm.mapper.model.DigestSize;
import com.ibm.mapper.model.IPrimitive;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.SaltLength;
import com.ibm.mapper.utils.DetectionLocation;
import javax.annotation.Nonnull;

/**
 *
 *
 * <h2>{@value #NAME}</h2>
 *
 * <p>
 *
 * <h3>Specification</h3>
 *
 * <ul>
 *   <li>https://www.blake2.net/blake2_20130129.pdf
 * </ul>
 *
 * <h3>Other Names and Related Standards</h3>
 *
 * <ul>
 * </ul>
 */
public final class BLAKE2b extends Algorithm implements MessageDigest {

    private static final String NAME = "BLAKE2b";

    public BLAKE2b(@Nonnull DetectionLocation detectionLocation) {
        this(false, detectionLocation);
    }

    public BLAKE2b(boolean isParallel, @Nonnull DetectionLocation detectionLocation) {
        super(NAME + (isParallel ? "p" : ""), MessageDigest.class, detectionLocation);
        this.put(new SaltLength(128, detectionLocation));
    }

    public BLAKE2b(
            int digestSize, boolean isParallel, @Nonnull DetectionLocation detectionLocation) {
        this(isParallel, detectionLocation);
        this.put(new DigestSize(digestSize, detectionLocation));
    }

    public BLAKE2b(@Nonnull final Class<? extends IPrimitive> asKind, @Nonnull BLAKE2b blake) {
        super(blake, asKind);
    }

    private BLAKE2b(@Nonnull BLAKE2b bLAKE2b) {
        super(bLAKE2b);
    }

    @Nonnull
    @Override
    protected BLAKE2b shallowCopy() {
        return new BLAKE2b(this);
    }
}
