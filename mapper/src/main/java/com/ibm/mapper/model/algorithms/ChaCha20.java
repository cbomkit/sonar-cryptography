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
import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.model.Mac;
import com.ibm.mapper.model.Padding;
import com.ibm.mapper.model.StreamCipher;
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
public final class ChaCha20 extends Algorithm implements StreamCipher {
    private static final String NAME = "ChaCha20";

    public ChaCha20(@Nonnull DetectionLocation detectionLocation) {
        super(NAME, StreamCipher.class, detectionLocation);
    }

    /** Returns the name "ChaCha20Poly1305" when it has a Poly1305 Mac node as child */
    @Override
    @Nonnull
    public String asString() {
        return this.hasChildOfType(Mac.class)
                .filter(node -> node instanceof Poly1305)
                .map(node -> this.name + ((IAlgorithm) node).getName())
                .orElse(this.name);
    }

    public ChaCha20(int keyLength, @Nonnull DetectionLocation detectionLocation) {
        this(detectionLocation);
        this.put(new KeyLength(keyLength, detectionLocation));
    }

    public ChaCha20(
            int keyLength, @Nonnull Padding padding, @Nonnull DetectionLocation detectionLocation) {
        this(detectionLocation);
        this.put(new KeyLength(keyLength, detectionLocation));
        this.put(padding);
    }

    public ChaCha20(@Nonnull final Class<? extends IPrimitive> asKind, @Nonnull ChaCha20 chaCha20) {
        super(chaCha20, asKind);
    }

    private ChaCha20(@Nonnull ChaCha20 chaCha20) {
        super(chaCha20);
    }

    @Nonnull
    @Override
    protected ChaCha20 shallowCopy() {
        return new ChaCha20(this);
    }
}
