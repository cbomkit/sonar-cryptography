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
import com.ibm.mapper.model.KeyAgreement;
import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.model.Oid;
import com.ibm.mapper.model.PublicKeyEncryption;
import com.ibm.mapper.model.Signature;
import com.ibm.mapper.utils.DetectionLocation;
import javax.annotation.Nonnull;

/**
 *
 *
 * <h2>FFDH (Finite Field Diffie-Hellman)</h2>
 *
 * <p>
 *
 * <h3>Specification</h3>
 *
 * <ul>
 *   <li>https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange
 *   <li>https://cyclonedx.org/schema/cryptography-defs.json (algorithmName: FFDH)
 * </ul>
 *
 * <h3>Other Names and Related Standards</h3>
 *
 * <ul>
 *   <li>Diffie-Hellman
 *   <li>DH
 * </ul>
 */
public final class DH extends Algorithm implements Signature, KeyAgreement, PublicKeyEncryption {
    private static final String NAME = "FFDH";

    @Override
    public @Nonnull String asString() {
        final StringBuilder sb = new StringBuilder(this.name);
        if (this.is(PublicKeyEncryption.class)) {
            this.hasChildOfType(KeyLength.class)
                    .ifPresent(k -> sb.append("-").append(k.asString()));
        }
        return sb.toString();
    }

    public DH(@Nonnull DetectionLocation detectionLocation) {
        this(PublicKeyEncryption.class, detectionLocation);
    }

    public DH(
            @Nonnull final Class<? extends IPrimitive> asKind,
            @Nonnull DetectionLocation detectionLocation) {
        super(NAME, asKind, detectionLocation);
        this.put(new Oid("1.2.840.113549.1.3.1", detectionLocation));
    }
}
