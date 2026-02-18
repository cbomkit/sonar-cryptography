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

import com.ibm.engine.model.context.MacContext;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.List;
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
    // HMAC (Hash-based Message Authentication Code)
    // ====================================================================

    private static final IDetectionRule<AstNode> EVP_MAC_HMAC_MD5 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_MAC_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("HMAC-MD5"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"HMAC\"")
                    .buildForContext(new MacContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_MAC_HMAC_SHA1 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_MAC_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("HMAC-SHA1"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"HMAC\"")
                    .buildForContext(new MacContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_MAC_HMAC_SHA224 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_MAC_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("HMAC-SHA224"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"HMAC\"")
                    .buildForContext(new MacContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_MAC_HMAC_SHA256 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_MAC_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("HMAC-SHA256"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"HMAC\"")
                    .buildForContext(new MacContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_MAC_HMAC_SHA384 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_MAC_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("HMAC-SHA384"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"HMAC\"")
                    .buildForContext(new MacContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_MAC_HMAC_SHA512 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_MAC_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("HMAC-SHA512"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"HMAC\"")
                    .buildForContext(new MacContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_MAC_HMAC_SHA3_224 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_MAC_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("HMAC-SHA3-224"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"HMAC\"")
                    .buildForContext(new MacContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_MAC_HMAC_SHA3_256 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_MAC_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("HMAC-SHA3-256"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"HMAC\"")
                    .buildForContext(new MacContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_MAC_HMAC_SHA3_384 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_MAC_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("HMAC-SHA3-384"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"HMAC\"")
                    .buildForContext(new MacContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_MAC_HMAC_SHA3_512 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_MAC_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("HMAC-SHA3-512"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"HMAC\"")
                    .buildForContext(new MacContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_MAC_HMAC_SHA512_224 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_MAC_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("HMAC-SHA512/224"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"HMAC\"")
                    .buildForContext(new MacContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_MAC_HMAC_SHA512_256 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_MAC_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("HMAC-SHA512/256"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"HMAC\"")
                    .buildForContext(new MacContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_MAC_HMAC_RIPEMD160 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_MAC_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("HMAC-RIPEMD160"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"HMAC\"")
                    .buildForContext(new MacContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_MAC_HMAC_BLAKE2B =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_MAC_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("HMAC-BLAKE2B"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"HMAC\"")
                    .buildForContext(new MacContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_MAC_HMAC_BLAKE2S =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_MAC_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("HMAC-BLAKE2S"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"HMAC\"")
                    .buildForContext(new MacContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_MAC_HMAC_SM3 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_MAC_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("HMAC-SM3"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"HMAC\"")
                    .buildForContext(new MacContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // CMAC (Cipher-based Message Authentication Code)
    // ====================================================================

    private static final IDetectionRule<AstNode> EVP_MAC_CMAC_AES128 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_MAC_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("CMAC-AES-128"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"CMAC\"")
                    .buildForContext(new MacContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_MAC_CMAC_AES192 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_MAC_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("CMAC-AES-192"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"CMAC\"")
                    .buildForContext(new MacContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_MAC_CMAC_AES256 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_MAC_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("CMAC-AES-256"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"CMAC\"")
                    .buildForContext(new MacContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_MAC_CMAC_3DES =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_MAC_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("CMAC-3DES"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"CMAC\"")
                    .buildForContext(new MacContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_MAC_CMAC_CAMELLIA128 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_MAC_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("CMAC-CAMELLIA-128"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"CMAC\"")
                    .buildForContext(new MacContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_MAC_CMAC_CAMELLIA192 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_MAC_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("CMAC-CAMELLIA-192"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"CMAC\"")
                    .buildForContext(new MacContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_MAC_CMAC_CAMELLIA256 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_MAC_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("CMAC-CAMELLIA-256"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"CMAC\"")
                    .buildForContext(new MacContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_MAC_CMAC_ARIA128 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_MAC_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("CMAC-ARIA-128"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"CMAC\"")
                    .buildForContext(new MacContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_MAC_CMAC_ARIA192 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_MAC_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("CMAC-ARIA-192"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"CMAC\"")
                    .buildForContext(new MacContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_MAC_CMAC_ARIA256 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_MAC_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("CMAC-ARIA-256"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"CMAC\"")
                    .buildForContext(new MacContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_MAC_CMAC_SM4 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_MAC_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("CMAC-SM4"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"CMAC\"")
                    .buildForContext(new MacContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // GMAC (Galois Message Authentication Code)
    // ====================================================================

    private static final IDetectionRule<AstNode> EVP_MAC_GMAC_AES128 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_MAC_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("GMAC-AES-128"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"GMAC\"")
                    .buildForContext(new MacContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_MAC_GMAC_AES192 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_MAC_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("GMAC-AES-192"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"GMAC\"")
                    .buildForContext(new MacContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_MAC_GMAC_AES256 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_MAC_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("GMAC-AES-256"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"GMAC\"")
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
                    .buildForContext(new MacContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private OpenSSLEvpMac() {
        // nothing
    }

    @Nonnull
    public static List<IDetectionRule<AstNode>> rules() {
        return List.of(
                // HMAC
                EVP_MAC_HMAC_MD5,
                EVP_MAC_HMAC_SHA1,
                EVP_MAC_HMAC_SHA224,
                EVP_MAC_HMAC_SHA256,
                EVP_MAC_HMAC_SHA384,
                EVP_MAC_HMAC_SHA512,
                EVP_MAC_HMAC_SHA512_224,
                EVP_MAC_HMAC_SHA512_256,
                EVP_MAC_HMAC_SHA3_224,
                EVP_MAC_HMAC_SHA3_256,
                EVP_MAC_HMAC_SHA3_384,
                EVP_MAC_HMAC_SHA3_512,
                EVP_MAC_HMAC_RIPEMD160,
                EVP_MAC_HMAC_BLAKE2B,
                EVP_MAC_HMAC_BLAKE2S,
                EVP_MAC_HMAC_SM3,
                // CMAC
                EVP_MAC_CMAC_AES128,
                EVP_MAC_CMAC_AES192,
                EVP_MAC_CMAC_AES256,
                EVP_MAC_CMAC_3DES,
                EVP_MAC_CMAC_CAMELLIA128,
                EVP_MAC_CMAC_CAMELLIA192,
                EVP_MAC_CMAC_CAMELLIA256,
                EVP_MAC_CMAC_ARIA128,
                EVP_MAC_CMAC_ARIA192,
                EVP_MAC_CMAC_ARIA256,
                EVP_MAC_CMAC_SM4,
                // GMAC
                EVP_MAC_GMAC_AES128,
                EVP_MAC_GMAC_AES192,
                EVP_MAC_GMAC_AES256,
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
                EVP_MAC_BLAKE2SMAC);
    }
}
