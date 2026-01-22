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
import com.ibm.mapper.model.Mode;
import com.ibm.mapper.model.Padding;
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
 *   <li>https://en.wikipedia.org/wiki/Triple_DES
 * </ul>
 *
 * <h3>Other Names and Related Standards</h3>
 *
 * <ul>
 *   <li>TripleDES
 *   <li>3DES
 *   <li>TDES
 * </ul>
 */
public final class DESede extends Algorithm implements BlockCipher, KeyWrap, Mac {

    private static final String NAME = "DESede";

    @Override
    public @Nonnull String asString() {
        final StringBuilder sb = new StringBuilder(this.name);
        this.hasChildOfType(KeyLength.class).ifPresent(k -> sb.append(k.asString()));
        this.hasChildOfType(Mode.class).ifPresent(m -> sb.append("-").append(m.asString()));
        this.hasChildOfType(Padding.class).ifPresent(p -> sb.append("-").append(p.asString()));
        return sb.toString();
    }

    public DESede(@Nonnull DetectionLocation detectionLocation) {
        super(NAME, BlockCipher.class, detectionLocation);
        this.put(BlockSize.ofDefault(64, detectionLocation));
    }

    public DESede(int keyLength, @Nonnull DetectionLocation detectionLocation) {
        this(detectionLocation);
        this.put(new KeyLength(keyLength, detectionLocation));
    }

    public DESede(int keyLength, @Nonnull Mode mode, @Nonnull DetectionLocation detectionLocation) {
        this(detectionLocation);
        this.put(new KeyLength(keyLength, detectionLocation));
        this.put(mode);
    }

    public DESede(
            int keyLength,
            @Nonnull Mode mode,
            @Nonnull Padding padding,
            @Nonnull DetectionLocation detectionLocation) {
        this(detectionLocation);
        this.put(new KeyLength(keyLength, detectionLocation));
        this.put(mode);
        this.put(padding);
    }

    public DESede(@Nonnull final Class<? extends IPrimitive> asKind, @Nonnull DESede desEde) {
        super(desEde, asKind);
    }
}
