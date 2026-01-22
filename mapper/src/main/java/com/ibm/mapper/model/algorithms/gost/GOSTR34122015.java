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
import com.ibm.mapper.model.AuthenticatedEncryption;
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
 *   <li>Kuznyechik
 * </ul>
 */
public final class GOSTR34122015 extends Algorithm implements BlockCipher, AuthenticatedEncryption {
    private static final String NAME = "GOSTR34122015";

    public GOSTR34122015(@Nonnull DetectionLocation detectionLocation) {
        super(NAME, BlockCipher.class, detectionLocation);
        this.put(BlockSize.ofDefault(128, detectionLocation));
        this.put(KeyLength.ofDefault(256, detectionLocation));
    }

    public GOSTR34122015(@Nonnull Mode mode, @Nonnull DetectionLocation detectionLocation) {
        this(detectionLocation);
        this.put(mode);
    }

    public GOSTR34122015(
            @Nonnull final Class<? extends IPrimitive> asKind,
            @Nonnull GOSTR34122015 gostr34122015) {
        super(gostr34122015, asKind);
    }
}
