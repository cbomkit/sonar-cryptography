/*
 * Sonar Cryptography Plugin
 * Copyright (C) 2026 PQCA
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
import com.ibm.mapper.model.IPrimitive;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.PasswordBasedKeyDerivationFunction;
import com.ibm.mapper.utils.DetectionLocation;
import javax.annotation.Nonnull;

/**
 *
 *
 * <h2>{@value #NAME}</h2>
 *
 * <p>The PKCS#12 key derivation function, which derives keys, IVs and MAC keys from a password and
 * a salt with a digest.
 *
 * <h3>Specification</h3>
 *
 * <ul>
 *   <li>https://www.rfc-editor.org/rfc/rfc7292#appendix-B
 * </ul>
 *
 * <h3>Other Names and Related Standards</h3>
 *
 * <ul>
 *   <li>PKCS#12 v1.1 appendix B
 * </ul>
 */
public final class PKCS12KDF extends Algorithm implements PasswordBasedKeyDerivationFunction {

    private static final String NAME = "PKCS12KDF";

    public PKCS12KDF(@Nonnull DetectionLocation detectionLocation) {
        super(NAME, PasswordBasedKeyDerivationFunction.class, detectionLocation);
    }

    @Override
    public @Nonnull String asString() {
        return this.hasChildOfType(MessageDigest.class)
                .map(digest -> this.name + "-" + ((IAlgorithm) digest).getName())
                .orElse(this.name);
    }

    private PKCS12KDF(@Nonnull PKCS12KDF algorithm) {
        super(algorithm);
    }

    @Nonnull
    @Override
    protected PKCS12KDF copy() {
        return new PKCS12KDF(this);
    }

    public PKCS12KDF(
            @Nonnull final Class<? extends IPrimitive> asKind, @Nonnull PKCS12KDF pkcs12kdf) {
        super(pkcs12kdf, asKind);
    }

    @Nonnull
    @Override
    public PKCS12KDF asKind(@Nonnull Class<? extends IPrimitive> kind) {
        return new PKCS12KDF(kind, this);
    }
}
