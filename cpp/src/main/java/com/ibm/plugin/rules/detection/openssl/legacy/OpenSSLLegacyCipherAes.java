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
package com.ibm.plugin.rules.detection.openssl.legacy;

import com.ibm.engine.rule.IDetectionRule;
import com.ibm.plugin.rules.detection.Memoize;
import com.ibm.plugin.rules.detection.openssl.cipher.OpenSSLEvpCipherRuleFactory;
import com.ibm.plugin.rules.detection.openssl.cipher.OpenSSLEvpCipherRuleFactory.LegacyEntry;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.List;
import java.util.function.Supplier;
import javax.annotation.Nonnull;

/** Detection rules for OpenSSL legacy (pre-EVP) AES cipher APIs. */
public final class OpenSSLLegacyCipherAes {

    private static final String BUNDLE = "OpenSSL";

    private static final List<LegacyEntry> ENTRIES =
            List.of(
                    new LegacyEntry("AES_set_encrypt_key", "AES"),
                    new LegacyEntry("AES_set_decrypt_key", "AES"),
                    new LegacyEntry("AES_ecb_encrypt", "AES-ECB"),
                    new LegacyEntry("AES_cbc_encrypt", "AES-CBC"),
                    new LegacyEntry("AES_cfb128_encrypt", "AES-CFB128"),
                    new LegacyEntry("AES_ofb128_encrypt", "AES-OFB"),
                    new LegacyEntry("AES_ige_encrypt", "AES-IGE"),
                    new LegacyEntry("AES_cfb1_encrypt", "AES-CFB1"),
                    new LegacyEntry("AES_cfb8_encrypt", "AES-CFB8"),
                    new LegacyEntry("AES_bi_ige_encrypt", "AES-BI-IGE"));

    private OpenSSLLegacyCipherAes() {
        // private
    }

    @Nonnull
    private static List<IDetectionRule<AstNode>> buildRules() {
        return OpenSSLEvpCipherRuleFactory.buildLegacy(BUNDLE, ENTRIES);
    }

    private static final Supplier<List<IDetectionRule<AstNode>>> RULES =
            Memoize.of(OpenSSLLegacyCipherAes::buildRules);

    @Nonnull
    public static List<IDetectionRule<AstNode>> rules() {
        return RULES.get();
    }
}
