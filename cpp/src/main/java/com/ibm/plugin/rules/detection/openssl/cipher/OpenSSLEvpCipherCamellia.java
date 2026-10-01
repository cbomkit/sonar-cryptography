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
package com.ibm.plugin.rules.detection.openssl.cipher;

import com.ibm.engine.rule.IDetectionRule;
import com.ibm.plugin.rules.detection.Memoize;
import com.ibm.plugin.rules.detection.openssl.cipher.OpenSSLEvpCipherRuleFactory.Entry;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.List;
import java.util.function.Supplier;
import javax.annotation.Nonnull;

/**
 * Detection rules for OpenSSL EVP Camellia cipher algorithm specifiers.
 *
 * <p>Covers Camellia-128/192/256 across all EVP modes (ECB, CBC, CFB variants, OFB, CTR).
 */
public final class OpenSSLEvpCipherCamellia {

    private static final String BUNDLE = "OpenSSL";

    private static final List<Entry> ENTRIES =
            List.of(
                    // Camellia-128
                    new Entry("EVP_camellia_128_ecb", "CAMELLIA-128-ECB"),
                    new Entry("EVP_camellia_128_cbc", "CAMELLIA-128-CBC"),
                    new Entry("EVP_camellia_128_cfb128", "CAMELLIA-128-CFB"),
                    new Entry("EVP_camellia_128_cfb1", "CAMELLIA-128-CFB1"),
                    new Entry("EVP_camellia_128_cfb8", "CAMELLIA-128-CFB8"),
                    new Entry("EVP_camellia_128_cfb128", "CAMELLIA-128-CFB128"),
                    new Entry("EVP_camellia_128_ofb", "CAMELLIA-128-OFB"),
                    new Entry("EVP_camellia_128_ctr", "CAMELLIA-128-CTR"),
                    // Camellia-192
                    new Entry("EVP_camellia_192_ecb", "CAMELLIA-192-ECB"),
                    new Entry("EVP_camellia_192_cbc", "CAMELLIA-192-CBC"),
                    new Entry("EVP_camellia_192_cfb128", "CAMELLIA-192-CFB"),
                    new Entry("EVP_camellia_192_cfb1", "CAMELLIA-192-CFB1"),
                    new Entry("EVP_camellia_192_cfb8", "CAMELLIA-192-CFB8"),
                    new Entry("EVP_camellia_192_cfb128", "CAMELLIA-192-CFB128"),
                    new Entry("EVP_camellia_192_ofb", "CAMELLIA-192-OFB"),
                    new Entry("EVP_camellia_192_ctr", "CAMELLIA-192-CTR"),
                    // Camellia-256
                    new Entry("EVP_camellia_256_ecb", "CAMELLIA-256-ECB"),
                    new Entry("EVP_camellia_256_cbc", "CAMELLIA-256-CBC"),
                    new Entry("EVP_camellia_256_cfb128", "CAMELLIA-256-CFB"),
                    new Entry("EVP_camellia_256_cfb1", "CAMELLIA-256-CFB1"),
                    new Entry("EVP_camellia_256_cfb8", "CAMELLIA-256-CFB8"),
                    new Entry("EVP_camellia_256_cfb128", "CAMELLIA-256-CFB128"),
                    new Entry("EVP_camellia_256_ofb", "CAMELLIA-256-OFB"),
                    new Entry("EVP_camellia_256_ctr", "CAMELLIA-256-CTR"));

    private OpenSSLEvpCipherCamellia() {
        // private
    }

    @Nonnull
    private static List<IDetectionRule<AstNode>> buildRules() {
        return OpenSSLEvpCipherRuleFactory.build(BUNDLE, ENTRIES);
    }

    private static final Supplier<List<IDetectionRule<AstNode>>> RULES =
            Memoize.of(OpenSSLEvpCipherCamellia::buildRules);

    @Nonnull
    public static List<IDetectionRule<AstNode>> rules() {
        return RULES.get();
    }
}
