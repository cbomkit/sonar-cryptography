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
import com.ibm.mapper.model.AuthenticatedEncryption;
import com.ibm.mapper.model.IPrimitive;
import com.ibm.mapper.model.mode.CBC;
import com.ibm.mapper.model.padding.PKCS7;
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
 *   *
 * </ul>
 */
public final class Fernet extends Algorithm implements AuthenticatedEncryption {
    private static final String NAME = "Fernet";

    public Fernet(@Nonnull DetectionLocation detectionLocation) {
        super(NAME, AuthenticatedEncryption.class, detectionLocation);
        this.put(
                new AES(
                        128,
                        new CBC(detectionLocation),
                        new PKCS7(detectionLocation),
                        detectionLocation));
        this.put(new HMAC(new SHA2(256, detectionLocation)));
    }

    public Fernet(@Nonnull final Class<? extends IPrimitive> asKind, @Nonnull Fernet fernet) {
        super(fernet, asKind);
    }

    private Fernet(@Nonnull Fernet fernet) {
        super(fernet);
    }

    @Nonnull
    @Override
    protected Fernet shallowCopy() {
        return new Fernet(this);
    }
}
