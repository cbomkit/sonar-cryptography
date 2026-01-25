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
import com.ibm.mapper.model.IPrimitive;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.Oid;
import com.ibm.mapper.utils.DetectionLocation;
import javax.annotation.Nonnull;

/**
 *
 *
 * <h2>SHA-1 (Secure Hash Algorithm 1)</h2>
 *
 * <p>
 *
 * <h3>Specification</h3>
 *
 * <ul>
 *   <li>https://csrc.nist.gov/projects/hash-functions
 *   <li>https://cyclonedx.org/schema/cryptography-defs.json (algorithmName: SHA-1)
 * </ul>
 */
public final class SHA extends Algorithm implements MessageDigest {

    public SHA(@Nonnull DetectionLocation detectionLocation) {
        this(MessageDigest.class, detectionLocation);
    }

    public SHA(
            @Nonnull final Class<? extends IPrimitive> asKind,
            @Nonnull DetectionLocation detectionLocation) {
        super("SHA-1", asKind, detectionLocation);
        this.put(BlockSize.ofDefault(512, detectionLocation));
        this.put(new DigestSize(160, detectionLocation));
        this.put(new Oid("1.3.14.3.2.26", detectionLocation));
    }

    public SHA(@Nonnull final Class<? extends IPrimitive> asKind, @Nonnull SHA sha) {
        super(sha, asKind);
    }
}
