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
 *   <li>See 6.2.2 of https://www.shoup.net/iso/std6.pdf (ISO 18033)
 * </ul>
 *
 * <h3>Other Names and Related Standards</h3>
 *
 * <ul>
 *   <li>ISO 18033
 * </ul>
 */
public final class KDF1 extends Algorithm implements KeyDerivationFunction {

    private static final String NAME = "KDF1";

    public KDF1(@Nonnull DetectionLocation detectionLocation) {
        super(NAME, KeyDerivationFunction.class, detectionLocation);
    }

    public KDF1(@Nonnull MessageDigest messageDigest) {
        this(messageDigest.getDetectionContext());
        this.put(messageDigest);
    }

    private KDF1(@Nonnull KDF1 kDF1) {
        super(kDF1);
    }

    @Nonnull
    @Override
    protected KDF1 shallowCopy() {
        return new KDF1(this);
    }
}
