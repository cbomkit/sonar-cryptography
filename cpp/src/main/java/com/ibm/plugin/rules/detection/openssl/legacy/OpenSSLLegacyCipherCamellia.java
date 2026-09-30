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

import com.ibm.engine.model.Size;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.plugin.rules.detection.Memoize;
import com.ibm.plugin.rules.detection.openssl.cipher.OpenSSLEvpCipherRuleFactory;
import com.ibm.plugin.rules.detection.openssl.cipher.OpenSSLEvpCipherRuleFactory.LegacyEntry;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.List;
import java.util.function.Supplier;
import javax.annotation.Nonnull;

/** Detection rules for OpenSSL legacy (pre-EVP) Camellia cipher APIs. */
public final class OpenSSLLegacyCipherCamellia {

    private static final String BUNDLE = "OpenSSL";

    // function(s), label, number of arguments[, argument giving the key size, its unit];
    // keyAt: the argument giving the key schedule, followed to its key setup
    private static final List<LegacyEntry> ENTRIES =
            List.of(
                    new LegacyEntry("Camellia_set_key", "CAMELLIA", 3, 1, Size.UnitType.BIT),
                    new LegacyEntry("Camellia_ecb_encrypt", "CAMELLIA-ECB", 4).keyAt(2),
                    new LegacyEntry("Camellia_cbc_encrypt", "CAMELLIA-CBC", 6).keyAt(3),
                    new LegacyEntry("Camellia_cfb128_encrypt", "CAMELLIA-CFB128", 7).keyAt(3),
                    new LegacyEntry("Camellia_cfb1_encrypt", "CAMELLIA-CFB1", 7).keyAt(3),
                    new LegacyEntry("Camellia_cfb8_encrypt", "CAMELLIA-CFB8", 7).keyAt(3),
                    new LegacyEntry("Camellia_ofb128_encrypt", "CAMELLIA-OFB", 6).keyAt(3),
                    new LegacyEntry("Camellia_ctr128_encrypt", "CAMELLIA-CTR", 7).keyAt(3));

    private OpenSSLLegacyCipherCamellia() {
        // private
    }

    @Nonnull
    private static List<IDetectionRule<AstNode>> buildRules() {
        return OpenSSLEvpCipherRuleFactory.buildLegacy(BUNDLE, ENTRIES);
    }

    private static final Supplier<List<IDetectionRule<AstNode>>> RULES =
            Memoize.of(OpenSSLLegacyCipherCamellia::buildRules);

    @Nonnull
    public static List<IDetectionRule<AstNode>> rules() {
        return RULES.get();
    }
}
