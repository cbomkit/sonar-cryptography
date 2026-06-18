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
 * <p>
 *
 * <h3>Specification</h3>
 *
 * <ul>
 * </ul>
 *
 * <h3>Other Names and Related Standards</h3>
 *
 * <ul>
 *   *
 * </ul>
 */
public final class SHA2 extends Algorithm implements MessageDigest {
    private static final String NAME = "SHA";

    public SHA2(int digestSize, @Nonnull DetectionLocation detectionLocation) {
        super(NAME + digestSize, MessageDigest.class, detectionLocation);
        this.put(new DigestSize(digestSize, detectionLocation));
    }

    public SHA2(
            int digestSize,
            @Nonnull MessageDigest preHash,
            @Nonnull DetectionLocation detectionLocation) {
        super(buildPreHashName(digestSize, preHash), MessageDigest.class, detectionLocation);
        this.put(new DigestSize(digestSize, detectionLocation));
        this.put(preHash);
    }

    public SHA2(
            int digestSize,
            @Nonnull final Class<? extends IPrimitive> asKind,
            @Nonnull DetectionLocation detectionLocation) {
        super(NAME + digestSize, asKind, detectionLocation);
    }

    public SHA2(@Nonnull final Class<? extends IPrimitive> asKind, @Nonnull SHA2 sha2) {
        super(sha2, asKind);
    }

    @Nonnull
    private static String buildPreHashName(int digestSize, @Nonnull MessageDigest preHash) {
        return preHash.getDigestSize()
                .map(size -> NAME + size.asString() + "/" + digestSize)
                .orElse(NAME + digestSize);
    }

    private SHA2(@Nonnull SHA2 sHA2) {
        super(sHA2);
    }

    @Nonnull
    @Override
    protected SHA2 shallowCopy() {
        return new SHA2(this);
    }
}
