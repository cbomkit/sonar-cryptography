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
import com.ibm.mapper.model.Cipher;
import com.ibm.mapper.model.Mac;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.PasswordBasedEncryption;
import com.ibm.mapper.utils.DetectionLocation;
import javax.annotation.Nonnull;

public final class PKCS12PBE extends Algorithm implements PasswordBasedEncryption {
    // https://www.rfc-editor.org/rfc/rfc7292#appendix-B

    private static final String NAME = "PKCS12"; // id-PKCS12PBE

    public PKCS12PBE(@Nonnull DetectionLocation detectionLocation) {
        super(NAME, PasswordBasedEncryption.class, detectionLocation);
    }

    public PKCS12PBE(@Nonnull Mac mac, @Nonnull Cipher cipher) {
        this(mac.getDetectionContext());
        this.put(mac);
        this.put(cipher);
    }

    public PKCS12PBE(@Nonnull MessageDigest digest, @Nonnull Cipher cipher) {
        this(digest.getDetectionContext());
        this.put(digest);
        this.put(cipher);
    }

    public PKCS12PBE(@Nonnull Mac mac) {
        this(mac.getDetectionContext());
        this.put(mac);
    }
}
