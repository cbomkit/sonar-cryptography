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
 *   <li>https://eprint.iacr.org/2016/098.pdf
 * </ul>
 *
 * <h3>Other Names and Related Standards</h3>
 *
 * <ul>
 * </ul>
 */
public final class HarakaV2 extends Algorithm implements MessageDigest {

    private static final String NAME = "Haraka v2";

    /** Returns a name of the form "Haraka-XXX v2" where XXX is the block size */
    @Override
    @Nonnull
    public String asString() {
        StringBuilder builtName = new StringBuilder(this.name);

        Optional<INode> blockSize = this.hasChildOfType(BlockSize.class);

        if (blockSize.isPresent()) {
            builtName = new StringBuilder("Haraka-");
            builtName.append(blockSize.get().asString()).append(" v2");
        }

        return builtName.toString();
    }

    public HarakaV2(@Nonnull DetectionLocation detectionLocation) {
        super(NAME, MessageDigest.class, detectionLocation);
        this.put(new DigestSize(256, detectionLocation));
    }

    public HarakaV2(int blockSize, @Nonnull DetectionLocation detectionLocation) {
        this(detectionLocation);
        this.put(new BlockSize(blockSize, detectionLocation));
    }

    public HarakaV2(@Nonnull final Class<? extends IPrimitive> asKind, @Nonnull HarakaV2 haraka) {
        super(haraka, asKind);
    }

    private HarakaV2(@Nonnull HarakaV2 harakaV2) {
        super(harakaV2);
    }

    @Nonnull
    @Override
    protected HarakaV2 shallowCopy() {
        return new HarakaV2(this);
    }
}
