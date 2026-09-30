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
import com.ibm.mapper.model.PublicKeyEncryption;
import com.ibm.mapper.utils.DetectionLocation;
import javax.annotation.Nonnull;

/**
 *
 *
 * <h2>{@value #NAME}</h2>
 *
 * <p>Hybrid public key encryption, made of a key encapsulation mechanism, a key derivation function
 * and an AEAD cipher, which are children of this node.
 *
 * <h3>Specification</h3>
 *
 * <ul>
 *   <li>https://www.rfc-editor.org/rfc/rfc9180
 * </ul>
 *
 * <h3>Other Names and Related Standards</h3>
 *
 * <ul>
 *   <li>Hybrid Public Key Encryption
 * </ul>
 */
public final class HPKE extends Algorithm implements PublicKeyEncryption {

    private static final String NAME = "HPKE";

    public HPKE(@Nonnull DetectionLocation detectionLocation) {
        super(NAME, PublicKeyEncryption.class, detectionLocation);
    }

    private HPKE(@Nonnull HPKE algorithm) {
        super(algorithm);
    }

    @Nonnull
    @Override
    protected HPKE copy() {
        return new HPKE(this);
    }

    public HPKE(@Nonnull final Class<? extends IPrimitive> asKind, @Nonnull HPKE hpke) {
        super(hpke, asKind);
    }

    @Nonnull
    @Override
    public HPKE asKind(@Nonnull Class<? extends IPrimitive> kind) {
        return new HPKE(kind, this);
    }
}
