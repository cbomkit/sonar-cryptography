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
package com.ibm.plugin.rules.detection;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.RuleSets;
import com.ibm.plugin.rules.detection.openssl.cipher.OpenSSLEvpCipher;
import com.ibm.plugin.rules.detection.openssl.cipher.OpenSSLEvpCipherFetch;
import com.ibm.plugin.rules.detection.openssl.digest.OpenSSLEvpMessageDigest;
import com.ibm.plugin.rules.detection.openssl.kdf.OpenSSLEvpKdf;
import com.ibm.plugin.rules.detection.openssl.keyagreement.OpenSSLEvpKeyAgreement;
import com.ibm.plugin.rules.detection.openssl.keygen.OpenSSLEvpKeyGen;
import com.ibm.plugin.rules.detection.openssl.keygen.OpenSSLEvpKeyGenRsa;
import com.ibm.plugin.rules.detection.openssl.keygen.OpenSSLEvpKeyUsage;
import com.ibm.plugin.rules.detection.openssl.legacy.OpenSSLLegacyCipher;
import com.ibm.plugin.rules.detection.openssl.legacy.OpenSSLLegacyDh;
import com.ibm.plugin.rules.detection.openssl.legacy.OpenSSLLegacyDigest;
import com.ibm.plugin.rules.detection.openssl.legacy.OpenSSLLegacyDsa;
import com.ibm.plugin.rules.detection.openssl.legacy.OpenSSLLegacyEc;
import com.ibm.plugin.rules.detection.openssl.legacy.OpenSSLLegacyMac;
import com.ibm.plugin.rules.detection.openssl.legacy.OpenSSLLegacyRsa;
import com.ibm.plugin.rules.detection.openssl.mac.OpenSSLEvpMac;
import com.ibm.plugin.rules.detection.openssl.rand.OpenSSLRand;
import com.ibm.plugin.rules.detection.openssl.signature.OpenSSLEvpSignature;
import com.ibm.plugin.rules.detection.openssl.ssl.OpenSSLLibssl;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.List;
import org.junit.jupiter.api.Test;

class CxxDetectionRulesTest {

    @Test
    void testRulesRegistered() {
        List<IDetectionRule<AstNode>> rules = RuleSets.rulesOf(CxxDetectionRules.class);

        assertThat(rules).isNotEmpty();
        assertThat(rules).doesNotContainNull();
    }

    /**
     * Asserts {@link CxxDetectionRules}'s size against the independently-computed sum of each of
     * the 18 OpenSSL rule bundles' own {@code rules().size()}, rather than a hardcoded total: the
     * sum tracks itself when a rule is added to any one bundle, while still catching a bundle
     * removed from (or duplicated in) {@code OpenSSLDetectionRules}'s aggregation.
     */
    @Test
    void testAllEighteenOpenSslRuleBundlesAreAggregated() {
        int expectedTotal =
                RuleSets.rulesOf(OpenSSLEvpCipher.class).size()
                        + RuleSets.rulesOf(OpenSSLEvpCipherFetch.class).size()
                        + RuleSets.rulesOf(OpenSSLEvpMessageDigest.class).size()
                        + RuleSets.rulesOf(OpenSSLEvpMac.class).size()
                        + RuleSets.rulesOf(OpenSSLEvpSignature.class).size()
                        + RuleSets.rulesOf(OpenSSLEvpKeyGen.class).size()
                        + RuleSets.rulesOf(OpenSSLEvpKeyUsage.Signatures.class).size()
                        + RuleSets.rulesOf(OpenSSLEvpKeyGenRsa.KeyGenerationSettings.class).size()
                        + RuleSets.rulesOf(OpenSSLEvpKdf.class).size()
                        + RuleSets.rulesOf(OpenSSLEvpKeyAgreement.class).size()
                        + RuleSets.rulesOf(OpenSSLRand.class).size()
                        + RuleSets.rulesOf(OpenSSLLegacyCipher.class).size()
                        + RuleSets.rulesOf(OpenSSLLegacyDigest.class).size()
                        + RuleSets.rulesOf(OpenSSLLegacyMac.class).size()
                        + RuleSets.rulesOf(OpenSSLLegacyRsa.class).size()
                        + RuleSets.rulesOf(OpenSSLLegacyDsa.class).size()
                        + RuleSets.rulesOf(OpenSSLLegacyEc.class).size()
                        + RuleSets.rulesOf(OpenSSLLegacyDh.class).size()
                        + RuleSets.rulesOf(OpenSSLLibssl.class).size();

        assertThat(RuleSets.rulesOf(CxxDetectionRules.class)).hasSize(expectedTotal);
    }
}
