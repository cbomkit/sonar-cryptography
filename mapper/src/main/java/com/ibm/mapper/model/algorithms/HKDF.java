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
import com.ibm.mapper.model.KeyDerivationFunction;
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
 *   <li>https://en.wikipedia.org/wiki/HKDF
 * </ul>
 *
 * <h3>Other Names and Related Standards</h3>
 *
 * <ul>
 *   <li>RFC 5869
 * </ul>
 */
public final class HKDF extends Algorithm implements KeyDerivationFunction {

    private static final String NAME = "HKDF";

    public HKDF(@Nonnull DetectionLocation detectionLocation) {
        super(NAME, KeyDerivationFunction.class, detectionLocation);
    }

    public HKDF(@Nonnull MessageDigest messageDigest) {
        this(messageDigest.getDetectionContext());
        this.put(messageDigest);
    }

    @Override
    public @Nonnull String asString() {
        return this.hasChildOfType(MessageDigest.class)
                .map(digest -> this.name + "-" + ((IAlgorithm) digest).getName())
                .orElse(this.name);
    }

    private HKDF(@Nonnull HKDF hKDF) {
        super(hKDF);
    }

    @Nonnull
    @Override
    protected HKDF shallowCopy() {
        return new HKDF(this);
    }
}
