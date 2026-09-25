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
 * Detection rules for OpenSSL EVP DES and 3DES cipher algorithm specifiers.
 *
 * <p>Covers single DES, 3DES EDE (2-key) and EDE3 (3-key) across all EVP modes, plus DESX and the
 * EDE3 key-wrap variant.
 */
public final class OpenSSLEvpCipherDes {

    private static final String BUNDLE = "OpenSSL";

    private static final List<Entry> ENTRIES =
            List.of(
                    // DES/3DES
                    new Entry("EVP_des_cbc", "DES-CBC"),
                    new Entry("EVP_des_ecb", "DES-ECB"),
                    new Entry("EVP_des_ede3_cbc", "DESede3-CBC"),
                    // Single DES additional modes
                    new Entry("EVP_des_cfb64", "DES-CFB"),
                    new Entry("EVP_des_cfb1", "DES-CFB1"),
                    new Entry("EVP_des_cfb8", "DES-CFB8"),
                    new Entry("EVP_des_cfb64", "DES-CFB64"),
                    new Entry("EVP_des_ofb", "DES-OFB"),
                    // 3DES EDE (2-key)
                    new Entry("EVP_des_ede", "DESede"),
                    new Entry("EVP_des_ede_ecb", "DESede-ECB"),
                    new Entry("EVP_des_ede_cbc", "DESede-CBC"),
                    new Entry("EVP_des_ede_cfb64", "DESede-CFB64"),
                    new Entry("EVP_des_ede_ofb", "DESede-OFB"),
                    // 3DES EDE3 (3-key) additional modes
                    new Entry("EVP_des_ede3", "DESede3"),
                    new Entry("EVP_des_ede3_ecb", "DESede3-ECB"),
                    new Entry("EVP_des_ede3_cfb1", "DESede3-CFB1"),
                    new Entry("EVP_des_ede3_cfb8", "DESede3-CFB8"),
                    new Entry("EVP_des_ede3_cfb64", "DESede3-CFB64"),
                    new Entry("EVP_des_ede3_ofb", "DESede3-OFB"),
                    // DESX
                    new Entry("EVP_desx_cbc", "DESX-CBC"),
                    // EVP_des_ede3_wrap
                    new Entry("EVP_des_ede3_wrap", "DES-EDE3-WRAP"));

    private OpenSSLEvpCipherDes() {
        // private
    }

    @Nonnull
    private static List<IDetectionRule<AstNode>> buildRules() {
        return OpenSSLEvpCipherRuleFactory.build(BUNDLE, ENTRIES);
    }

    private static final Supplier<List<IDetectionRule<AstNode>>> RULES =
            Memoize.of(OpenSSLEvpCipherDes::buildRules);

    @Nonnull
    public static List<IDetectionRule<AstNode>> rules() {
        return RULES.get();
    }
}
