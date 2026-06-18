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
import com.ibm.mapper.model.IPrimitive;
import com.ibm.mapper.model.KeyAgreement;
import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.Oid;
import com.ibm.mapper.model.Padding;
import com.ibm.mapper.model.PublicKeyEncryption;
import com.ibm.mapper.model.Signature;
import com.ibm.mapper.model.padding.OAEP;
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
public final class RSA extends Algorithm implements KeyAgreement, Signature, PublicKeyEncryption {
    private static final String NAME = "RSA";
    private static final String OID = "1.2.840.113549.1.1.1";

    @Override
    public @Nonnull String asString() {
        if (this.is(Signature.class)) {
            return this.hasChildOfType(MessageDigest.class)
                    .map(node -> node.asString() + "with" + this.name)
                    .orElse(this.name);
        } else if (this.is(PublicKeyEncryption.class)) {
            Optional<INode> keyLength = this.hasChildOfType(KeyLength.class);
            if (this.hasChildOfType(Padding.class).map(OAEP.class::isInstance).orElse(false)) {
                return this.name + "-OAEP";
            } else if (keyLength.isPresent()) {
                return this.name + "-" + keyLength.get().asString();
            }
        }
        return this.name;
    }

    public RSA(@Nonnull DetectionLocation detectionLocation) {
        super(NAME, PublicKeyEncryption.class, detectionLocation);
        this.put(new Oid(OID, detectionLocation));
    }

    public RSA(int keyLength, @Nonnull DetectionLocation detectionLocation) {
        super(NAME, PublicKeyEncryption.class, detectionLocation);
        this.put(new KeyLength(keyLength, detectionLocation));
        this.put(new Oid(OID, detectionLocation));
    }

    public RSA(
            @Nonnull final Class<? extends IPrimitive> asKind,
            @Nonnull DetectionLocation detectionLocation) {
        super(NAME, asKind, detectionLocation);
        this.put(new Oid(OID, detectionLocation));
    }

    public RSA(@Nonnull final Class<? extends IPrimitive> asKind, @Nonnull RSA rsa) {
        super(rsa, asKind);
    }

    private RSA(@Nonnull final RSA rsa) {
        super(rsa);
    }

    @Nonnull
    @Override
    protected RSA shallowCopy() {
        return new RSA(this);
    }
}
