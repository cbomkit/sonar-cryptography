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
import com.ibm.mapper.model.InitializationVectorLength;
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
 *   <li>HC-256: https://en.wikipedia.org/wiki/HC-256
 *   <li>HC-128: https://www.ecrypt.eu.org/stream/p3ciphers/hc/hc128_p3.pdf
 * </ul>
 *
 * <h3>Other Names and Related Standards</h3>
 *
 * <ul>
 * </ul>
 */
public final class HC extends Algorithm implements StreamCipher {

    private static final String NAME = "HC";

    /** Returns a name of the form "HC-XXX" where XXX is the key length */
    @Override
    public @Nonnull String asString() {
        return this.hasChildOfType(KeyLength.class)
                .map(node -> this.name + "-" + node.asString())
                .orElse(this.name);
    }

    public HC(int keyLength, @Nonnull DetectionLocation detectionLocation) {
        super(NAME, StreamCipher.class, detectionLocation);
        this.put(new KeyLength(keyLength, detectionLocation));
        this.put(new InitializationVectorLength(keyLength, detectionLocation));
    }

    public HC(@Nonnull final Class<? extends IPrimitive> asKind, @Nonnull HC hc) {
        super(hc, asKind);
    }

    private HC(@Nonnull HC hC) {
        super(hC);
    }

    @Nonnull
    @Override
    protected HC shallowCopy() {
        return new HC(this);
    }
}
