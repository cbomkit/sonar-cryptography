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
import com.ibm.mapper.model.BlockSize;
import com.ibm.mapper.model.IPrimitive;
import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.model.KeyWrap;
import com.ibm.mapper.model.Mac;
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
 *   <li>https://en.wikipedia.org/wiki/Kalyna_(cipher)
 *   <li>https://eprint.iacr.org/2015/650.pdf
 * </ul>
 *
 * <h3>Other Names and Related Standards</h3>
 *
 * <ul>
 *   <li>DSTU 7624:2014
 * </ul>
 */
public final class Kalyna extends Algorithm implements BlockCipher, Mac, KeyWrap {

    private static final String NAME = "Kalyna";

    /**
     * Returns a name of the form "Kalyna-XXX/YYY" where XXX is the block size and YYY is the key
     * length
     */
    @Override
    @Nonnull
    public String asString() {
        StringBuilder builtName = new StringBuilder(this.name);
        this.hasChildOfType(BlockSize.class).ifPresent(b -> builtName.append("-" + b.asString()));
        this.hasChildOfType(KeyLength.class).ifPresent(k -> builtName.append("/" + k.asString()));
        return builtName.toString();
    }

    public Kalyna(@Nonnull DetectionLocation detectionLocation) {
        super(NAME, BlockCipher.class, detectionLocation);
    }

    public Kalyna(int blockSize, @Nonnull DetectionLocation detectionLocation) {
        this(detectionLocation);
        this.put(new BlockSize(blockSize, detectionLocation));
    }

    public Kalyna(int blockSize, int keyLength, @Nonnull DetectionLocation detectionLocation) {
        this(detectionLocation);
        this.put(new BlockSize(blockSize, detectionLocation));
        this.put(new KeyLength(keyLength, detectionLocation));
    }

    public Kalyna(@Nonnull final Class<? extends IPrimitive> asKind, @Nonnull Kalyna kalyna) {
        super(kalyna, asKind);
    }

    private Kalyna(@Nonnull Kalyna kalyna) {
        super(kalyna);
    }

    @Nonnull
    @Override
    protected Kalyna shallowCopy() {
        return new Kalyna(this);
    }
}
