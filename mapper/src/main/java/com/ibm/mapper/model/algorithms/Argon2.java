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
import com.ibm.mapper.model.PasswordBasedKeyDerivationFunction;
import com.ibm.mapper.utils.DetectionLocation;
import javax.annotation.Nonnull;

/**
 *
 *
 * <h2>Argon2</h2>
 *
 * <p>Memory-hard password hashing and key derivation function, in its data-dependent (Argon2d),
 * data-independent (Argon2i) or hybrid (Argon2id) variant.
 *
 * <h3>Specification</h3>
 *
 * <ul>
 *   <li>https://www.rfc-editor.org/rfc/rfc9106
 *   <li>https://cyclonedx.org/schema/cryptography-defs.json (family: Argon2)
 * </ul>
 *
 * <h3>Other Names and Related Standards</h3>
 *
 * <ul>
 *   <li>Argon2d, Argon2i, Argon2id
 * </ul>
 */
public final class Argon2 extends Algorithm implements PasswordBasedKeyDerivationFunction {

    private static final String NAME = "Argon2";

    public enum Variant {
        D("d"),
        I("i"),
        ID("id");

        @Nonnull private final String suffix;

        Variant(@Nonnull String suffix) {
            this.suffix = suffix;
        }
    }

    public Argon2(@Nonnull Variant variant, @Nonnull DetectionLocation detectionLocation) {
        super(NAME + variant.suffix, PasswordBasedKeyDerivationFunction.class, detectionLocation);
    }

    private Argon2(@Nonnull Argon2 algorithm) {
        super(algorithm);
    }

    @Nonnull
    @Override
    protected Argon2 copy() {
        return new Argon2(this);
    }

    public Argon2(@Nonnull final Class<? extends IPrimitive> asKind, @Nonnull Argon2 argon2) {
        super(argon2, asKind);
    }

    @Nonnull
    @Override
    public Argon2 asKind(@Nonnull Class<? extends IPrimitive> kind) {
        return new Argon2(kind, this);
    }
}
