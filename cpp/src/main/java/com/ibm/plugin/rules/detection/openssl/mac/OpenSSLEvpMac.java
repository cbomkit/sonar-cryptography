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
package com.ibm.plugin.rules.detection.openssl.mac;

import com.ibm.engine.model.context.DigestContext;
import com.ibm.engine.model.context.MacContext;
import com.ibm.engine.model.factory.AlgorithmFactory;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.plugin.rules.detection.openssl.digest.OpenSSLNameCanonicalizerFactory;
import com.ibm.plugin.rules.detection.openssl.kdf.OpenSSLParamsScannerFactory;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.List;
import java.util.Map;
import javax.annotation.Nonnull;

/**
 * Detection rules for OpenSSL EVP MAC (Message Authentication Code) algorithms.
 *
 * <p>These rules detect calls to OpenSSL MAC functions using the EVP_MAC API. OpenSSL 3.x uses
 * EVP_MAC_fetch() to obtain MAC algorithms like HMAC, CMAC, GMAC, Poly1305, etc.
 *
 * <p>Covers HMAC (with various digests), CMAC, GMAC, Poly1305, SipHash, KMAC, and BLAKE2 MAC.
 */
@SuppressWarnings("java:S1192")
public final class OpenSSLEvpMac {

    private static final String BUNDLE = "OpenSSL";

    // ====================================================================
    // HMAC / CMAC / GMAC fetch — one finding per MAC family (the real fetched name); the
    // digest (HMAC) or cipher (CMAC/GMAC) is set later via EVP_MAC_CTX_set_params and is a
    // separate, independently traced finding (see EVP_MAC_CTX_SET_PARAMS below).
    // ====================================================================

    private static final IDetectionRule<AstNode> EVP_MAC_HMAC_FETCH =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_MAC_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("HMAC"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"HMAC\"")
                    .withMethodParameter("*")
                    .buildForContext(new MacContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_MAC_CMAC_FETCH =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_MAC_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("CMAC"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"CMAC\"")
                    .withMethodParameter("*")
                    .buildForContext(new MacContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_MAC_GMAC_FETCH =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_MAC_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("GMAC"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"GMAC\"")
                    .withMethodParameter("*")
                    .buildForContext(new MacContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // EVP_MAC_CTX_set_params — the real digest (OSSL_MAC_PARAM_DIGEST, "digest") or cipher
    // (OSSL_MAC_PARAM_CIPHER, "cipher") entry in the OSSL_PARAM array.
    // ====================================================================

    /** OpenSSL cipher name (e.g. {@code "AES-128-CBC"}) → CMAC/GMAC identifier string. */
    private static final Map<String, String> CIPHER_NAMES =
            Map.ofEntries(
                    Map.entry("AES-128-CBC", "CMAC-AES-128"),
                    Map.entry("AES-192-CBC", "CMAC-AES-192"),
                    Map.entry("AES-256-CBC", "CMAC-AES-256"),
                    Map.entry("DES-EDE3-CBC", "CMAC-3DES"),
                    Map.entry("CAMELLIA-128-CBC", "CMAC-CAMELLIA-128"),
                    Map.entry("CAMELLIA-192-CBC", "CMAC-CAMELLIA-192"),
                    Map.entry("CAMELLIA-256-CBC", "CMAC-CAMELLIA-256"),
                    Map.entry("ARIA-128-CBC", "CMAC-ARIA-128"),
                    Map.entry("ARIA-192-CBC", "CMAC-ARIA-192"),
                    Map.entry("ARIA-256-CBC", "CMAC-ARIA-256"),
                    Map.entry("SM4-CBC", "CMAC-SM4"));

    private static final IDetectionRule<AstNode> EVP_MAC_CTX_SET_PARAMS_DIGEST =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_MAC_CTX_set_params")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(
                            new OpenSSLParamsScannerFactory(
                                    "digest", OpenSSLNameCanonicalizerFactory.DIGEST_NAMES))
                    .buildForContext(new DigestContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_MAC_CTX_SET_PARAMS_CIPHER =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_MAC_CTX_set_params")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(new OpenSSLParamsScannerFactory("cipher", CIPHER_NAMES))
                    .buildForContext(new MacContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // Poly1305
    // ====================================================================

    private static final IDetectionRule<AstNode> EVP_MAC_POLY1305 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_MAC_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("POLY1305"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"Poly1305\"")
                    .withMethodParameter("*")
                    .buildForContext(new MacContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // SipHash
    // ====================================================================

    private static final IDetectionRule<AstNode> EVP_MAC_SIPHASH_2_4 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_MAC_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SIPHASH-2-4"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"SipHash\"")
                    .withMethodParameter("*")
                    .buildForContext(new MacContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_MAC_SIPHASH_4_8 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_MAC_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SIPHASH-4-8"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"SipHash\"")
                    .withMethodParameter("*")
                    .buildForContext(new MacContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // KMAC (Keccak Message Authentication Code)
    // ====================================================================

    private static final IDetectionRule<AstNode> EVP_MAC_KMAC128 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_MAC_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("KMAC128"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"KMAC128\"")
                    .withMethodParameter("*")
                    .buildForContext(new MacContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_MAC_KMAC256 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_MAC_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("KMAC256"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"KMAC256\"")
                    .withMethodParameter("*")
                    .buildForContext(new MacContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // BLAKE2 MAC
    // ====================================================================

    private static final IDetectionRule<AstNode> EVP_MAC_BLAKE2BMAC =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_MAC_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("BLAKE2BMAC"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"BLAKE2BMAC\"")
                    .withMethodParameter("*")
                    .buildForContext(new MacContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_MAC_BLAKE2SMAC =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_MAC_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("BLAKE2SMAC"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"BLAKE2SMAC\"")
                    .withMethodParameter("*")
                    .buildForContext(new MacContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_Q_MAC =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_Q_mac")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .buildForContext(new MacContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private OpenSSLEvpMac() {
        // nothing
    }

    @Nonnull
    public static List<IDetectionRule<AstNode>> rules() {
        return List.of(
                // HMAC / CMAC / GMAC fetch
                EVP_MAC_HMAC_FETCH,
                EVP_MAC_CMAC_FETCH,
                EVP_MAC_GMAC_FETCH,
                // EVP_MAC_CTX_set_params
                EVP_MAC_CTX_SET_PARAMS_DIGEST,
                EVP_MAC_CTX_SET_PARAMS_CIPHER,
                // Poly1305
                EVP_MAC_POLY1305,
                // SipHash
                EVP_MAC_SIPHASH_2_4,
                EVP_MAC_SIPHASH_4_8,
                // KMAC
                EVP_MAC_KMAC128,
                EVP_MAC_KMAC256,
                // BLAKE2 MAC
                EVP_MAC_BLAKE2BMAC,
                EVP_MAC_BLAKE2SMAC,
                EVP_Q_MAC);
    }
}
