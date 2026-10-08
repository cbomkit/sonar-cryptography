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
package com.ibm.plugin.rules.detection.openssl;

import com.ibm.engine.rule.DetectionRuleSet;
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
import java.util.stream.Stream;
import javax.annotation.Nonnull;

/**
 * Aggregates all OpenSSL cryptography detection rules.
 *
 * <p>This class collects detection rules from all OpenSSL API categories:
 *
 * <ul>
 *   <li>EVP message digest functions ({@code EVP_sha256}, {@code EVP_md5}, etc.)
 *   <li>EVP cipher functions ({@code EVP_aes_256_gcm}, {@code EVP_chacha20_poly1305}, etc.)
 *   <li>EVP MAC functions ({@code EVP_MAC_fetch} with HMAC, CMAC, GMAC, etc.)
 *   <li>SSL/TLS protocol functions ({@code TLS_method}, {@code SSL_CTX_new}, etc.)
 * </ul>
 */
public final class OpenSSLDetectionRules extends DetectionRuleSet<AstNode> {

    @Nonnull
    @Override
    protected List<IDetectionRule<AstNode>> buildRules() {
        return Stream.of(
                        // EVP API - Modern OpenSSL 3.x functions
                        RuleSets.rulesOf(OpenSSLEvpCipher.class).stream(),
                        RuleSets.rulesOf(OpenSSLEvpCipherFetch.class).stream(),
                        RuleSets.rulesOf(OpenSSLEvpMessageDigest.class).stream(),
                        RuleSets.rulesOf(OpenSSLEvpMac.class).stream(),
                        RuleSets.rulesOf(OpenSSLEvpSignature.class).stream(),
                        RuleSets.rulesOf(OpenSSLEvpKeyGen.class).stream(),
                        // signatures with a key given to them, e.g. loaded from a file
                        RuleSets.rulesOf(OpenSSLEvpKeyUsage.Signatures.class).stream(),
                        RuleSets.rulesOf(OpenSSLEvpKeyGenRsa.KeyGenerationSettings.class).stream(),
                        RuleSets.rulesOf(OpenSSLEvpKdf.class).stream(),
                        RuleSets.rulesOf(OpenSSLEvpKeyAgreement.class).stream(),
                        RuleSets.rulesOf(OpenSSLRand.class).stream(),
                        // Legacy API - Deprecated but widely used
                        RuleSets.rulesOf(OpenSSLLegacyCipher.class).stream(),
                        RuleSets.rulesOf(OpenSSLLegacyDigest.class).stream(),
                        RuleSets.rulesOf(OpenSSLLegacyMac.class).stream(),
                        RuleSets.rulesOf(OpenSSLLegacyRsa.class).stream(),
                        RuleSets.rulesOf(OpenSSLLegacyDsa.class).stream(),
                        RuleSets.rulesOf(OpenSSLLegacyEc.class).stream(),
                        RuleSets.rulesOf(OpenSSLLegacyDh.class).stream(),
                        // SSL/TLS Protocol API
                        RuleSets.rulesOf(OpenSSLLibssl.class).stream())
                .flatMap(i -> i)
                .toList();
    }
}
