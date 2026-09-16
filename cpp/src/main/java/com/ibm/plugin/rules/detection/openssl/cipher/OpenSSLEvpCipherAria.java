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
 * Detection rules for OpenSSL EVP ARIA cipher algorithm specifiers.
 *
 * <p>Covers ARIA-128/192/256 (the Korean national standard cipher, RFC 5794) across all EVP modes
 * (ECB, CBC, CFB variants, OFB, CTR, GCM, CCM).
 */
public final class OpenSSLEvpCipherAria {

    private static final String BUNDLE = "OpenSSL";

    private static final List<Entry> ENTRIES =
            List.of(
                    // ARIA-128
                    new Entry("EVP_aria_128_ecb", "ARIA-128-ECB"),
                    new Entry("EVP_aria_128_cbc", "ARIA-128-CBC"),
                    new Entry("EVP_aria_128_cfb128", "ARIA-128-CFB"),
                    new Entry("EVP_aria_128_cfb1", "ARIA-128-CFB1"),
                    new Entry("EVP_aria_128_cfb8", "ARIA-128-CFB8"),
                    new Entry("EVP_aria_128_cfb128", "ARIA-128-CFB128"),
                    new Entry("EVP_aria_128_ofb", "ARIA-128-OFB"),
                    new Entry("EVP_aria_128_ctr", "ARIA-128-CTR"),
                    new Entry("EVP_aria_128_gcm", "ARIA-128-GCM"),
                    new Entry("EVP_aria_128_ccm", "ARIA-128-CCM"),
                    // ARIA-192
                    new Entry("EVP_aria_192_ecb", "ARIA-192-ECB"),
                    new Entry("EVP_aria_192_cbc", "ARIA-192-CBC"),
                    new Entry("EVP_aria_192_cfb128", "ARIA-192-CFB"),
                    new Entry("EVP_aria_192_cfb1", "ARIA-192-CFB1"),
                    new Entry("EVP_aria_192_cfb8", "ARIA-192-CFB8"),
                    new Entry("EVP_aria_192_cfb128", "ARIA-192-CFB128"),
                    new Entry("EVP_aria_192_ofb", "ARIA-192-OFB"),
                    new Entry("EVP_aria_192_ctr", "ARIA-192-CTR"),
                    new Entry("EVP_aria_192_gcm", "ARIA-192-GCM"),
                    new Entry("EVP_aria_192_ccm", "ARIA-192-CCM"),
                    // ARIA-256
                    new Entry("EVP_aria_256_ecb", "ARIA-256-ECB"),
                    new Entry("EVP_aria_256_cbc", "ARIA-256-CBC"),
                    new Entry("EVP_aria_256_cfb128", "ARIA-256-CFB"),
                    new Entry("EVP_aria_256_cfb1", "ARIA-256-CFB1"),
                    new Entry("EVP_aria_256_cfb8", "ARIA-256-CFB8"),
                    new Entry("EVP_aria_256_cfb128", "ARIA-256-CFB128"),
                    new Entry("EVP_aria_256_ofb", "ARIA-256-OFB"),
                    new Entry("EVP_aria_256_ctr", "ARIA-256-CTR"),
                    new Entry("EVP_aria_256_gcm", "ARIA-256-GCM"),
                    new Entry("EVP_aria_256_ccm", "ARIA-256-CCM"));

    private OpenSSLEvpCipherAria() {
        // private
    }

    @Nonnull
    private static List<IDetectionRule<AstNode>> buildRules() {
        return OpenSSLEvpCipherRuleFactory.build(BUNDLE, ENTRIES);
    }

    private static final Supplier<List<IDetectionRule<AstNode>>> RULES =
            Memoize.of(OpenSSLEvpCipherAria::buildRules);

    @Nonnull
    public static List<IDetectionRule<AstNode>> rules() {
        return RULES.get();
    }
}
