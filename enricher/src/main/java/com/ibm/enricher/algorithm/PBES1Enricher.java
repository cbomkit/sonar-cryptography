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
package com.ibm.enricher.algorithm;

import com.ibm.enricher.IEnricher;
import com.ibm.mapper.model.Cipher;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.Oid;
import com.ibm.mapper.model.algorithms.DES;
import com.ibm.mapper.model.algorithms.MD2;
import com.ibm.mapper.model.algorithms.MD5;
import com.ibm.mapper.model.algorithms.PBES1;
import com.ibm.mapper.model.algorithms.RC2;
import com.ibm.mapper.model.algorithms.RC4;
import com.ibm.mapper.model.algorithms.SHA;
import com.ibm.mapper.model.algorithms.TripleDES;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public class PBES1Enricher implements IEnricher {

    @Override
    @Nonnull
    public INode enrich(@Nonnull INode node) {
        if (node instanceof PBES1 pbes1) {
            final MessageDigest digest = pbes1.getDigest().orElse(null);
            final Cipher cipher = pbes1.getCipher().orElse(null);

            if (digest != null && cipher != null) {
                final String oidValue = resolveOid(digest, cipher);
                if (oidValue != null) {
                    pbes1.put(new Oid(oidValue, pbes1.getDetectionContext()));
                }
            }
        }
        return node;
    }

    @Nullable private String resolveOid(@Nonnull MessageDigest digest, @Nonnull Cipher cipher) {
        if (digest instanceof MD2) {
            if (cipher instanceof DES) return "1.2.840.113549.1.5.1";
            if (cipher instanceof RC2) return "1.2.840.113549.1.5.4";
        } else if (digest instanceof MD5) {
            if (cipher instanceof DES) return "1.2.840.113549.1.5.3";
            if (cipher instanceof RC2) return "1.2.840.113549.1.5.6";
        } else if (digest instanceof SHA) {
            // PKCS#5
            if (cipher instanceof DES) return "1.2.840.113549.1.5.10";

            // PKCS#12
            final int keyLength = cipher.getKeyLength().map(KeyLength::getValue).orElse(-1);
            if (cipher instanceof RC2) {
                if (keyLength == 128) return "1.2.840.113549.1.12.1.5";
                if (keyLength == 40) return "1.2.840.113549.1.12.1.6";
                return "1.2.840.113549.1.5.11"; // PKCS#5 default
            }
            if (cipher instanceof RC4) {
                if (keyLength == 128) return "1.2.840.113549.1.12.1.1";
                if (keyLength == 40) return "1.2.840.113549.1.12.1.2";
                // No PKCS#5 OID exists for SHA1+RC4 with other key lengths; null is intentional.
            }
            if (cipher instanceof TripleDES) {
                if (keyLength == 192 || keyLength == 168) return "1.2.840.113549.1.12.1.3";
                if (keyLength == 128 || keyLength == 112) return "1.2.840.113549.1.12.1.4";
            }
        }
        return null;
    }
}
