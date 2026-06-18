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
import com.ibm.mapper.model.PublicKeyEncryption;
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
 *   <li>https://en.wikipedia.org/wiki/Naccache–Stern_cryptosystem
 * </ul>
 *
 * <h3>Other Names and Related Standards</h3>
 *
 * <ul>
 * </ul>
 */
public final class NaccacheStern extends Algorithm implements PublicKeyEncryption {
    // https://en.wikipedia.org/wiki/Naccache–Stern_cryptosystem

    private static final String NAME = "Naccache-Stern";

    public NaccacheStern(@Nonnull DetectionLocation detectionLocation) {
        super(NAME, PublicKeyEncryption.class, detectionLocation);
    }

    public NaccacheStern(int keyLength, @Nonnull DetectionLocation detectionLocation) {
        this(detectionLocation);
        this.put(new KeyLength(keyLength, detectionLocation));
    }

    public NaccacheStern(
            @Nonnull final Class<? extends IPrimitive> asKind,
            @Nonnull NaccacheStern naccacheStern) {
        super(naccacheStern, asKind);
    }

    private NaccacheStern(@Nonnull NaccacheStern naccacheStern) {
        super(naccacheStern);
    }

    @Nonnull
    @Override
    protected NaccacheStern shallowCopy() {
        return new NaccacheStern(this);
    }
}
