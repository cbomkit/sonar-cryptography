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
import com.ibm.plugin.rules.detection.openssl.cipher.OpenSSLEvpCipherRuleFactory;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.List;
import javax.annotation.Nonnull;

/** Detection rules for OpenSSL legacy (pre-EVP) SEED cipher APIs. */
public final class OpenSSLLegacyCipherSeed extends OpenSSLEvpCipherRuleFactory {

    private static final String BUNDLE = "OpenSSL";

    // function(s), label, number of arguments[, argument giving the key size, its unit];
    // keyAt: the argument giving the key schedule, followed to its key setup
    private static final List<LegacyEntry> ENTRIES =
            List.of(
                    new LegacyEntry("SEED_set_key", "SEED", 2).setsUpKey(),
                    new LegacyEntry("SEED_ecb_encrypt", "SEED-ECB", 4).keyAt(2),
                    new LegacyEntry("SEED_cbc_encrypt", "SEED-CBC", 6).keyAt(3),
                    new LegacyEntry("SEED_cfb128_encrypt", "SEED-CFB", 7).keyAt(3),
                    new LegacyEntry("SEED_ofb128_encrypt", "SEED-OFB", 6).keyAt(3));

    @Nonnull
    @Override
    protected List<IDetectionRule<AstNode>> buildRules() {
        return OpenSSLEvpCipherRuleFactory.buildLegacy(BUNDLE, ENTRIES);
    }
}
