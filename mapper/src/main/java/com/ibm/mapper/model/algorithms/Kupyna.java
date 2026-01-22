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
import com.ibm.mapper.model.BlockSize;
import com.ibm.mapper.model.DigestSize;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.IPrimitive;
import com.ibm.mapper.model.InitializationVectorLength;
import com.ibm.mapper.model.MessageDigest;
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
 *   <li>https://eprint.iacr.org/2015/885.pdf
 * </ul>
 *
 * <h3>Other Names and Related Standards</h3>
 *
 * <ul>
 *   <li>DSTU 7564:2014
 * </ul>
 */
public final class Kupyna extends Algorithm implements MessageDigest {

    private static final String NAME = "Kupyna";

    /** Returns a name of the form "Kupyna-XXX" where XXX is the digest size */
    @Override
    @Nonnull
    public String asString() {
        StringBuilder builtName = new StringBuilder(this.name);

        Optional<INode> digestSize = this.hasChildOfType(DigestSize.class);

        if (digestSize.isPresent()) {
            builtName.append("-").append(digestSize.get().asString());
        }

        return builtName.toString();
    }

    public Kupyna(@Nonnull DetectionLocation detectionLocation) {
        super(NAME, MessageDigest.class, detectionLocation);
    }

    public Kupyna(int digestSize, @Nonnull DetectionLocation detectionLocation) {
        this(detectionLocation);
        this.put(new DigestSize(digestSize, detectionLocation));

        if (digestSize >= 8 && digestSize <= 256) {
            this.put(BlockSize.ofDefault(512, detectionLocation));
            this.put(new InitializationVectorLength(512, detectionLocation));
        }
        if (digestSize > 256 && digestSize <= 512) {
            this.put(BlockSize.ofDefault(1024, detectionLocation));
            this.put(new InitializationVectorLength(1024, detectionLocation));
        }
    }

    public Kupyna(@Nonnull final Class<? extends IPrimitive> asKind, @Nonnull Kupyna kupyna) {
        super(kupyna, asKind);
    }
}
