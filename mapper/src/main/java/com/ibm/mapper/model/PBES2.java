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
package com.ibm.mapper.model;

import com.ibm.mapper.utils.DetectionLocation;
import javax.annotation.Nonnull;

public class PBES2 extends Algorithm implements PasswordBasedEncryption {
    // https://datatracker.ietf.org/doc/html/rfc2898#section-6.2
    // https://datatracker.ietf.org/doc/html/rfc2898#appendix-A.4

    private static final String NAME = "PBES2"; // id-PBES2

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

    private PBES2(@Nonnull PBES2 pBES2) {
        super(pBES2);
    }

    @Nonnull
    @Override
    protected PBES2 shallowCopy() {
        return new PBES2(this);
    }
}
