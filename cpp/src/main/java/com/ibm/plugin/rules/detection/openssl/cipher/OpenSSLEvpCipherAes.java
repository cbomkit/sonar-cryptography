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
 * Detection rules for OpenSSL EVP AES cipher algorithm specifiers.
 *
 * <p>Covers AES-128/192/256 across all EVP modes (CBC, ECB, GCM, CTR, CCM, CFB variants, OFB, XTS,
 * OCB, key wrap) plus the AES-CBC-HMAC combined TLS Encrypt-then-MAC ciphers.
 */
public final class OpenSSLEvpCipherAes {

    private static final String BUNDLE = "OpenSSL";

    private static final List<Entry> ENTRIES =
            List.of(
                    // AES-128
                    new Entry("EVP_aes_128_cbc", "AES-128-CBC"),
                    new Entry("EVP_aes_128_ecb", "AES-128-ECB"),
                    new Entry("EVP_aes_128_gcm", "AES-128-GCM"),
                    new Entry("EVP_aes_128_ctr", "AES-128-CTR"),
                    new Entry("EVP_aes_128_ccm", "AES-128-CCM"),
                    new Entry("EVP_aes_128_cfb128", "AES-128-CFB"),
                    new Entry("EVP_aes_128_cfb1", "AES-128-CFB1"),
                    new Entry("EVP_aes_128_cfb8", "AES-128-CFB8"),
                    new Entry("EVP_aes_128_cfb128", "AES-128-CFB128"),
                    new Entry("EVP_aes_128_ofb", "AES-128-OFB"),
                    new Entry("EVP_aes_128_xts", "AES-128-XTS"),
                    new Entry("EVP_aes_128_ocb", "AES-128-OCB"),
                    new Entry("EVP_aes_128_wrap", "AES-128-WRAP"),
                    new Entry("EVP_aes_128_wrap_pad", "AES-128-WRAP-PAD"),
                    // AES-192
                    new Entry("EVP_aes_192_cbc", "AES-192-CBC"),
                    new Entry("EVP_aes_192_ecb", "AES-192-ECB"),
                    new Entry("EVP_aes_192_gcm", "AES-192-GCM"),
                    new Entry("EVP_aes_192_ctr", "AES-192-CTR"),
                    new Entry("EVP_aes_192_ccm", "AES-192-CCM"),
                    new Entry("EVP_aes_192_cfb128", "AES-192-CFB"),
                    new Entry("EVP_aes_192_cfb1", "AES-192-CFB1"),
                    new Entry("EVP_aes_192_cfb8", "AES-192-CFB8"),
                    new Entry("EVP_aes_192_cfb128", "AES-192-CFB128"),
                    new Entry("EVP_aes_192_ofb", "AES-192-OFB"),
                    new Entry("EVP_aes_192_ocb", "AES-192-OCB"),
                    new Entry("EVP_aes_192_wrap", "AES-192-WRAP"),
                    new Entry("EVP_aes_192_wrap_pad", "AES-192-WRAP-PAD"),
                    // AES-256
                    new Entry("EVP_aes_256_cbc", "AES-256-CBC"),
                    new Entry("EVP_aes_256_ecb", "AES-256-ECB"),
                    new Entry("EVP_aes_256_gcm", "AES-256-GCM"),
                    new Entry("EVP_aes_256_ctr", "AES-256-CTR"),
                    new Entry("EVP_aes_256_ccm", "AES-256-CCM"),
                    new Entry("EVP_aes_256_cfb128", "AES-256-CFB"),
                    new Entry("EVP_aes_256_cfb1", "AES-256-CFB1"),
                    new Entry("EVP_aes_256_cfb8", "AES-256-CFB8"),
                    new Entry("EVP_aes_256_cfb128", "AES-256-CFB128"),
                    new Entry("EVP_aes_256_ofb", "AES-256-OFB"),
                    new Entry("EVP_aes_256_xts", "AES-256-XTS"),
                    new Entry("EVP_aes_256_ocb", "AES-256-OCB"),
                    new Entry("EVP_aes_256_wrap", "AES-256-WRAP"),
                    new Entry("EVP_aes_256_wrap_pad", "AES-256-WRAP-PAD"),
                    // AES CBC-HMAC Combined Mode - TLS Encrypt-then-MAC
                    new Entry("EVP_aes_128_cbc_hmac_sha1", "AES-128-CBC-HMAC-SHA1"),
                    new Entry("EVP_aes_256_cbc_hmac_sha1", "AES-256-CBC-HMAC-SHA1"),
                    new Entry("EVP_aes_128_cbc_hmac_sha256", "AES-128-CBC-HMAC-SHA256"),
                    new Entry("EVP_aes_256_cbc_hmac_sha256", "AES-256-CBC-HMAC-SHA256"));

    private OpenSSLEvpCipherAes() {
        // private
    }

    @Nonnull
    private static List<IDetectionRule<AstNode>> buildRules() {
        return OpenSSLEvpCipherRuleFactory.build(BUNDLE, ENTRIES);
    }

    private static final Supplier<List<IDetectionRule<AstNode>>> RULES =
            Memoize.of(OpenSSLEvpCipherAes::buildRules);

    @Nonnull
    public static List<IDetectionRule<AstNode>> rules() {
        return RULES.get();
    }
}
