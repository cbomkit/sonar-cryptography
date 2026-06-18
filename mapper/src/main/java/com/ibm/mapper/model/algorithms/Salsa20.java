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
import com.ibm.mapper.model.IPrimitive;
import com.ibm.mapper.model.KeyLength;
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
 *   <li>https://en.wikipedia.org/wiki/Salsa20
 * </ul>
 *
 * <h3>Other Names and Related Standards</h3>
 *
 * <ul>
 * </ul>
 */
public final class Salsa20 extends Algorithm implements StreamCipher {

    private static final String NAME = "Salsa20";

    public Salsa20(@Nonnull DetectionLocation detectionLocation) {
        this(128, detectionLocation);
    }

    public Salsa20(int keyLength, @Nonnull DetectionLocation detectionLocation) {
        super(NAME, StreamCipher.class, detectionLocation);
        this.put(new KeyLength(keyLength, detectionLocation));
    }

    public Salsa20(@Nonnull final Class<? extends IPrimitive> asKind, @Nonnull Salsa20 salsa20) {
        super(salsa20, asKind);
    }

    private Salsa20(@Nonnull Salsa20 salsa20) {
        super(salsa20);
    }

    @Nonnull
    @Override
    protected Salsa20 shallowCopy() {
        return new Salsa20(this);
    }
}
