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
package com.ibm.mapper.model.algorithms.gost;

import com.ibm.mapper.model.Algorithm;
import com.ibm.mapper.model.BlockSize;
import com.ibm.mapper.model.DigestSize;
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
 *   <li>https://en.wikipedia.org/wiki/GOST_(hash_function)
 * </ul>
 *
 * <h3>Other Names and Related Standards</h3>
 *
 * <ul>
 *   <li>GOST R 34.11-94
 *   <li>GOST 34.311-95
 *   <li>Just "GOST"
 * </ul>
 */
public final class GOST341194 extends Algorithm implements MessageDigest {

    private static final String NAME = "GOST341194";

    public GOST341194(@Nonnull DetectionLocation detectionLocation) {
        super(NAME, MessageDigest.class, detectionLocation);
        this.put(BlockSize.ofDefault(256, detectionLocation));
        this.put(new DigestSize(256, detectionLocation));
        // The hash function is derived from this block cipher:
        this.put(new GOST28147(detectionLocation));
    }

    public GOST341194(
            @Nonnull final Class<? extends MessageDigest> asKind, @Nonnull GOST341194 gostr341194) {
        super(gostr341194, asKind);
    }
}
