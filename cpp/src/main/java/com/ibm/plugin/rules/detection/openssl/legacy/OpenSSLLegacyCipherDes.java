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

/** Detection rules for OpenSSL legacy (pre-EVP) DES and 3DES cipher APIs. */
public final class OpenSSLLegacyCipherDes {

    private static final String BUNDLE = "OpenSSL";

    private static final List<LegacyEntry> ENTRIES =
            List.of(
                    new LegacyEntry(
                            List.of("DES_set_key", "DES_set_key_checked", "DES_set_key_unchecked"),
                            "DES"),
                    new LegacyEntry("DES_ecb_encrypt", "DES-ECB"),
                    new LegacyEntry(List.of("DES_ncbc_encrypt", "DES_cbc_encrypt"), "DES-CBC"),
                    new LegacyEntry(List.of("DES_cfb64_encrypt", "DES_cfb_encrypt"), "DES-CFB"),
                    new LegacyEntry("DES_ofb64_encrypt", "DES-OFB"),
                    new LegacyEntry("DES_ede3_cbc_encrypt", "3DES-CBC"),
                    new LegacyEntry("DES_ecb3_encrypt", "3DES-ECB"),
                    new LegacyEntry(
                            List.of("DES_ede3_cfb64_encrypt", "DES_ede3_cfb_encrypt"), "3DES-CFB"),
                    new LegacyEntry("DES_ede3_ofb64_encrypt", "3DES-OFB"),
                    new LegacyEntry("DES_xcbc_encrypt", "DES-XCBC"));

    private OpenSSLLegacyCipherDes() {
        // private
    }

    @Nonnull
    private static List<IDetectionRule<AstNode>> buildRules() {
        return OpenSSLEvpCipherRuleFactory.buildLegacy(BUNDLE, ENTRIES);
    }

    private static final Supplier<List<IDetectionRule<AstNode>>> RULES =
            Memoize.of(OpenSSLLegacyCipherDes::buildRules);

    @Nonnull
    public static List<IDetectionRule<AstNode>> rules() {
        return RULES.get();
    }
}
