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
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.Mac;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.PasswordBasedKeyDerivationFunction;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.Optional;
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
 *   *
 * </ul>
 */
public final class PBKDF2 extends Algorithm implements PasswordBasedKeyDerivationFunction {
    private static final String NAME = "PBKDF2";

    @Override
    public @Nonnull String asString() {
        final StringBuilder sb = new StringBuilder(this.name + "-");
        final Optional<INode> mac = this.hasChildOfType(Mac.class);
        if (mac.isPresent()) {
            sb.append(mac.get().asString());
            return sb.toString();
        }

        final Optional<INode> digest = this.hasChildOfType(MessageDigest.class);
        if (digest.isPresent()) {
            sb.append(digest.get().asString());
            return sb.toString();
        }
        return this.name;
    }

    public PBKDF2(@Nonnull Mac mac) {
        super(NAME, PasswordBasedKeyDerivationFunction.class, mac.getDetectionContext());
        this.put(mac);
    }

    public PBKDF2(@Nonnull MessageDigest messageDigest) {
        super(NAME, PasswordBasedKeyDerivationFunction.class, messageDigest.getDetectionContext());
        this.put(messageDigest);
    }

    public PBKDF2(@Nonnull DetectionLocation detectionLocation) {
        super(NAME, PasswordBasedKeyDerivationFunction.class, detectionLocation);
    }

    private PBKDF2(@Nonnull PBKDF2 pBKDF2) {
        super(pBKDF2);
    }

    @Nonnull
    @Override
    protected PBKDF2 shallowCopy() {
        return new PBKDF2(this);
    }
}
