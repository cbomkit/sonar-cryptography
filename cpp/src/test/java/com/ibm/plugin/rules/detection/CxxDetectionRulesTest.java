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
import com.ibm.plugin.rules.detection.openssl.cipher.OpenSSLEvpCipher;
import com.ibm.plugin.rules.detection.openssl.cipher.OpenSSLEvpCipherFetch;
import com.ibm.plugin.rules.detection.openssl.digest.OpenSSLEvpMessageDigest;
import com.ibm.plugin.rules.detection.openssl.kdf.OpenSSLEvpKdf;
import com.ibm.plugin.rules.detection.openssl.keyagreement.OpenSSLEvpKeyAgreement;
import com.ibm.plugin.rules.detection.openssl.keygen.OpenSSLEvpKeyGen;
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
        List<IDetectionRule<AstNode>> rules = CxxDetectionRules.rules();

        assertThat(rules).isNotEmpty();
        assertThat(rules).doesNotContainNull();
    }

    /**
     * Asserts {@link CxxDetectionRules#rules()}'s size against the independently-computed sum of
     * each of the 17 OpenSSL rule bundles' own {@code rules().size()}, rather than a hardcoded
     * total: the sum tracks itself when a rule is added to any one bundle, while still catching a
     * bundle removed from (or duplicated in) {@code OpenSSLDetectionRules#rules()}'s aggregation.
     */
    @Test
    void testAllSeventeenOpenSslRuleBundlesAreAggregated() {
        int expectedTotal =
                OpenSSLEvpCipher.rules().size()
                        + OpenSSLEvpCipherFetch.rules().size()
                        + OpenSSLEvpMessageDigest.rules().size()
                        + OpenSSLEvpMac.rules().size()
                        + OpenSSLEvpSignature.rules().size()
                        + OpenSSLEvpKeyGen.rules().size()
                        + OpenSSLEvpKdf.rules().size()
                        + OpenSSLEvpKeyAgreement.rules().size()
                        + OpenSSLRand.rules().size()
                        + OpenSSLLegacyCipher.rules().size()
                        + OpenSSLLegacyDigest.rules().size()
                        + OpenSSLLegacyMac.rules().size()
                        + OpenSSLLegacyRsa.rules().size()
                        + OpenSSLLegacyDsa.rules().size()
                        + OpenSSLLegacyEc.rules().size()
                        + OpenSSLLegacyDh.rules().size()
                        + OpenSSLLibssl.rules().size();

        assertThat(CxxDetectionRules.rules()).hasSize(expectedTotal);
    }
}
