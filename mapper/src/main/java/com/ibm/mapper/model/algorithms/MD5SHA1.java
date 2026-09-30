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
import com.ibm.mapper.model.DigestSize;
import com.ibm.mapper.model.IPrimitive;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.utils.DetectionLocation;
import javax.annotation.Nonnull;

/**
 *
 *
 * <h2>{@value #NAME}</h2>
 *
 * <p>The concatenation of an MD5 and a SHA-1 digest of the same data (128 + 160 = 288 bits), used
 * by the TLS 1.0 and 1.1 handshake and PRF.
 *
 * <h3>Specification</h3>
 *
 * <ul>
 *   <li>https://www.rfc-editor.org/rfc/rfc4346#section-5
 * </ul>
 *
 * <h3>Other Names and Related Standards</h3>
 *
 * <ul>
 *   <li>OpenSSL {@code EVP_md5_sha1}
 * </ul>
 */
public final class MD5SHA1 extends Algorithm implements MessageDigest {

    private static final String NAME = "MD5-SHA1";

    public MD5SHA1(@Nonnull DetectionLocation detectionLocation) {
        super(NAME, MessageDigest.class, detectionLocation);
        this.put(new DigestSize(288, detectionLocation));
    }

    private MD5SHA1(@Nonnull MD5SHA1 algorithm) {
        super(algorithm);
    }

    @Nonnull
    @Override
    protected MD5SHA1 copy() {
        return new MD5SHA1(this);
    }

    public MD5SHA1(@Nonnull final Class<? extends IPrimitive> asKind, @Nonnull MD5SHA1 md5sha1) {
        super(md5sha1, asKind);
    }

    @Nonnull
    @Override
    public MD5SHA1 asKind(@Nonnull Class<? extends IPrimitive> kind) {
        return new MD5SHA1(kind, this);
    }
}
