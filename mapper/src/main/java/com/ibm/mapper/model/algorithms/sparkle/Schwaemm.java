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
package com.ibm.mapper.model.algorithms.sparkle;

import com.ibm.mapper.model.Algorithm;
import com.ibm.mapper.model.AuthenticatedEncryption;
import com.ibm.mapper.model.BlockCipher;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.model.NonceLength;
import com.ibm.mapper.model.TagLength;
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
 *   <li>https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/sparkle-spec-final.pdf
 * </ul>
 *
 * <h3>Other Names and Related Standards</h3>
 *
 * <ul>
 *   <li>Part of the Sparkle family
 * </ul>
 */
public class Schwaemm extends Algorithm implements AuthenticatedEncryption, BlockCipher {

    private static final String NAME = "Schwaemm";

    /**
     * Returns a name of the form "SchwaemmXXX-YYY" where XXX is the rate and YYY is the capacity
     */
    @Override
    @Nonnull
    public String asString() {
        StringBuilder builtName = new StringBuilder(this.name);

        Optional<INode> nonceLength /* rate */ = this.hasChildOfType(NonceLength.class);
        Optional<INode> keyLength /* capacity */ = this.hasChildOfType(KeyLength.class);

        if (nonceLength.isPresent() && keyLength.isPresent()) {
            builtName
                    .append(nonceLength.get().asString())
                    .append("-")
                    .append(keyLength.get().asString());
        }

        return builtName.toString();
    }

    public Schwaemm(@Nonnull DetectionLocation detectionLocation) {
        super(NAME, AuthenticatedEncryption.class, detectionLocation);
    }

    public Schwaemm(int rate, @Nonnull DetectionLocation detectionLocation) {
        this(detectionLocation);
        this.put(new NonceLength(rate, detectionLocation));
    }

    public Schwaemm(int rate, int capacity, @Nonnull DetectionLocation detectionLocation) {
        this(detectionLocation);
        this.put(new KeyLength(capacity, detectionLocation));
        this.put(new TagLength(capacity, detectionLocation));
        this.put(new NonceLength(rate, detectionLocation));
    }

    private Schwaemm(@Nonnull Schwaemm schwaemm) {
        super(schwaemm);
    }

    @Nonnull
    @Override
    protected Schwaemm shallowCopy() {
        return new Schwaemm(this);
    }
}
