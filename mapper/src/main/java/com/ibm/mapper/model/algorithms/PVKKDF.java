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
 * <p>The key derivation of the Microsoft PVK private key format, deriving an RC4 key from a
 * password with a digest.
 *
 * <h3>Specification</h3>
 *
 * <ul>
 *   <li>https://learn.microsoft.com/en-us/windows/win32/seccrypto/pvk-file-format
 * </ul>
 *
 * <h3>Other Names and Related Standards</h3>
 *
 * <ul>
 *   <li>Microsoft PVK
 * </ul>
 */
public final class PVKKDF extends Algorithm implements PasswordBasedKeyDerivationFunction {

    private static final String NAME = "PVKKDF";

    public PVKKDF(@Nonnull DetectionLocation detectionLocation) {
        super(NAME, PasswordBasedKeyDerivationFunction.class, detectionLocation);
    }

    @Override
    public @Nonnull String asString() {
        return this.hasChildOfType(MessageDigest.class)
                .map(digest -> this.name + "-" + ((IAlgorithm) digest).getName())
                .orElse(this.name);
    }

    private PVKKDF(@Nonnull PVKKDF algorithm) {
        super(algorithm);
    }

    @Nonnull
    @Override
    protected PVKKDF copy() {
        return new PVKKDF(this);
    }

    public PVKKDF(@Nonnull final Class<? extends IPrimitive> asKind, @Nonnull PVKKDF pvkkdf) {
        super(pvkkdf, asKind);
    }

    @Nonnull
    @Override
    public PVKKDF asKind(@Nonnull Class<? extends IPrimitive> kind) {
        return new PVKKDF(kind, this);
    }
}
