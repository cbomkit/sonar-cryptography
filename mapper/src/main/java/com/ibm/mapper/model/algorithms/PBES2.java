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
import com.ibm.mapper.model.BlockCipher;
import com.ibm.mapper.model.Cipher;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.Mac;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.Oid;
import com.ibm.mapper.model.PasswordBasedEncryption;
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
 *   <li><a href="https://doi.org/10.17487/RFC8018">RFC8018</a>
 * </ul>
 *
 * <h3>Other Names and Related Standards</h3>
 *
 * <ul>
 *   <li>PKCS#5
 * </ul>
 */
public final class PBES2 extends Algorithm implements PasswordBasedEncryption {
    private static final String NAME = "PBES2"; // id-PBES2

    @Override
    @Nonnull
    public String asString() {
        final Optional<INode> messageDigest = this.hasChildOfType(MessageDigest.class);
        final Optional<INode> mac = this.hasChildOfType(Mac.class);
        final Optional<INode> cipher = this.hasChildOfType(BlockCipher.class);

        final StringBuilder stringBuilder = new StringBuilder(this.name);

        if (cipher.isPresent()) {
            stringBuilder.append("-").append(cipher.get().asString());
            if (mac.isPresent()) {
                stringBuilder.append("-").append(mac.get().asString());
            } else
                messageDigest.ifPresent(
                        iNode -> stringBuilder.append("-").append(iNode.asString()));
        }
        return stringBuilder.toString();
    }

    public PBES2(@Nonnull DetectionLocation detectionLocation) {
        super(NAME, PasswordBasedEncryption.class, detectionLocation);
        this.put(new Oid("1.2.840.113549.1.5", detectionLocation));
    }

    public PBES2(@Nonnull Mac mac, @Nonnull Cipher cipher) {
        this(mac.getDetectionContext());
        this.put(mac);
        this.put(cipher);
    }

    public PBES2(@Nonnull MessageDigest digest, @Nonnull Cipher cipher) {
        this(digest.getDetectionContext());
        this.put(digest);
        this.put(cipher);
    }

    public PBES2(@Nonnull Mac mac) {
        this(mac.getDetectionContext());
        this.put(mac);
    }
}
