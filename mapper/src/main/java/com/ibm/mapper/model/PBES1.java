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
import java.util.Optional;
import javax.annotation.Nonnull;

public class PBES1 extends Algorithm implements PasswordBasedEncryption {
    // https://datatracker.ietf.org/doc/html/rfc2898#section-6.1
    // https://datatracker.ietf.org/doc/html/rfc2898#appendix-A.3

    private static final String NAME = "PBES1";

    /**
     * Returns a name of the form "pbeWithXXXAndYYY" where XXX is a hash function and YYY is a block
     * cipher
     */
    @Override
    @Nonnull
    public String asString() {
        final Optional<INode> messageDigest = this.hasChildOfType(MessageDigest.class);
        final Optional<INode> mac = this.hasChildOfType(Mac.class);
        final Optional<INode> cipher = this.hasChildOfType(BlockCipher.class);

        if (messageDigest.isPresent() && cipher.isPresent() && cipher.get() instanceof Cipher c) {
            return "pbeWith" + messageDigest.get().asString() + "And" + c.getName();
        } else if (mac.isPresent()) {
            String n = "pbeWith" + changeHMACNameing(mac.get().asString());
            return cipher.map(node -> n + "And" + node.asString()).orElse(n);
        }
        return this.name;
    }

    public PBES1(@Nonnull DetectionLocation detectionLocation) {
        super(NAME, PasswordBasedEncryption.class, detectionLocation);
    }

    // example: PBEWithHmacSHA1AndAES_128
    public PBES1(@Nonnull Mac mac, @Nonnull Cipher cipher) {
        this(mac.getDetectionContext());
        this.put(mac);
        this.put(cipher);
    }

    // example: PBEWithMD5AndDES
    public PBES1(@Nonnull MessageDigest digest, @Nonnull Cipher cipher) {
        this(digest.getDetectionContext());
        this.put(digest);
        this.put(cipher);
    }

    // example: PBEWithHmacSHA1
    public PBES1(@Nonnull Mac mac) {
        this(mac.getDetectionContext());
        this.put(mac);
    }

    private @Nonnull String changeHMACNameing(@Nonnull String hmacName) {
        if (!hmacName.contains("HMAC-")) {
            return hmacName;
        }
        return hmacName.replace("HMAC-", "Hmac");
    }

    private PBES1(@Nonnull PBES1 pBES1) {
        super(pBES1);
    }

    @Nonnull
    @Override
    protected PBES1 shallowCopy() {
        return new PBES1(this);
    }
}
