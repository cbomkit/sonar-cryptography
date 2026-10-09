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
import com.ibm.mapper.model.Mode;
import com.ibm.mapper.utils.DetectionLocation;
import javax.annotation.Nonnull;

/**
 *
 *
 * <h2>{@value #NAME}</h2>
 *
 * <p>DES with key whitening: the block is XORed with a second key before and a third key after the
 * DES encryption. The key is a 56-bit DES key and two 64-bit whitening keys (184 bits).
 *
 * <h3>Specification</h3>
 *
 * <ul>
 *   <li>https://en.wikipedia.org/wiki/DES-X
 * </ul>
 *
 * <h3>Other Names and Related Standards</h3>
 *
 * <ul>
 *   <li>DES-X, DESX-CBC (OpenSSL {@code EVP_desx_cbc}, {@code DES_xcbc_encrypt})
 * </ul>
 */
public final class DESX extends Algorithm implements BlockCipher {

    private static final String NAME = "DESX";

    @Override
    public @Nonnull String asString() {
        return composeName(true, true, false);
    }

    public DESX(@Nonnull DetectionLocation detectionLocation) {
        super(NAME, BlockCipher.class, detectionLocation);
        this.put(KeyLength.ofDefault(184, detectionLocation));
        this.put(BlockSize.ofDefault(64, detectionLocation));
    }

    public DESX(@Nonnull Mode mode, @Nonnull DetectionLocation detectionLocation) {
        this(detectionLocation);
        this.put(mode);
    }

    private DESX(@Nonnull DESX algorithm) {
        super(algorithm);
    }

    @Nonnull
    @Override
    protected DESX copy() {
        return new DESX(this);
    }

    public DESX(@Nonnull final Class<? extends IPrimitive> asKind, @Nonnull DESX desx) {
        super(desx, asKind);
    }

    @Nonnull
    @Override
    public DESX asKind(@Nonnull Class<? extends IPrimitive> kind) {
        return new DESX(kind, this);
    }
}
