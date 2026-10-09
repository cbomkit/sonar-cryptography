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
import com.ibm.mapper.model.KeyEncapsulationMechanism;
import com.ibm.mapper.utils.DetectionLocation;
import javax.annotation.Nonnull;

/**
 *
 *
 * <h2>{@value #NAME}</h2>
 *
 * <p>RSA secret-value encapsulation: a random secret value is encrypted with the RSA public key and
 * used directly as the shared secret. Unlike {@link RSAKEM}, no key derivation function is applied.
 *
 * <h3>Specification</h3>
 *
 * <ul>
 *   <li>See 7.2.1 of https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Br2.pdf
 * </ul>
 *
 * <h3>Other Names and Related Standards</h3>
 *
 * <ul>
 *   <li>NIST SP 800-56B
 * </ul>
 */
public final class RSASVE extends Algorithm implements KeyEncapsulationMechanism {

    private static final String NAME = "RSASVE";

    public RSASVE(@Nonnull DetectionLocation detectionLocation) {
        super(NAME, KeyEncapsulationMechanism.class, detectionLocation);
    }

    private RSASVE(@Nonnull RSASVE algorithm) {
        super(algorithm);
    }

    @Nonnull
    @Override
    protected RSASVE copy() {
        return new RSASVE(this);
    }

    public RSASVE(@Nonnull final Class<? extends IPrimitive> asKind, @Nonnull RSASVE rsasve) {
        super(rsasve, asKind);
    }

    @Nonnull
    @Override
    public RSASVE asKind(@Nonnull Class<? extends IPrimitive> kind) {
        return new RSASVE(kind, this);
    }
}
