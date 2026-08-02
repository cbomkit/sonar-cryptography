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

import com.ibm.engine.model.context.MacContext;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.plugin.rules.detection.openssl.cipher.OpenSSLEvpCipher;
import com.ibm.plugin.rules.detection.openssl.digest.OpenSSLEvpMessageDigest;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.List;
import javax.annotation.Nonnull;

/**
 * Detection rules for OpenSSL legacy MAC (Message Authentication Code) APIs.
 *
 * <p>These rules detect MAC operations using the legacy (pre-EVP) APIs. These APIs are deprecated
 * but still widely used in existing codebases.
 *
 * <p>Covers: HMAC, CMAC. Poly1305 is intentionally excluded — its {@code Poly1305_Init/
 * Update/Final} symbols are OpenSSL-internal (declared in {@code include/crypto/poly1305.h}, not
 * {@code include/openssl/}). Public Poly1305 access in OpenSSL 3.x is via {@code EVP_MAC_fetch(...,
 * "POLY1305", ...)}, handled by {@link com.ibm.plugin.rules.detection.openssl.mac.OpenSSLEvpMac}.
 */
@SuppressWarnings("java:S1192")
public final class OpenSSLLegacyMac {

    private static final String BUNDLE = "OpenSSL";

    // ====================================================================
    // Legacy HMAC functions
    // ====================================================================

    private static final IDetectionRule<AstNode> HMAC_CTX_NEW =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("HMAC_CTX_new")
                    .shouldBeDetectedAs(new ValueActionFactory<>("HMAC"))
                    .withoutParameters()
                    .buildForContext(new MacContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> HMAC_CTX_RESET =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("HMAC_CTX_reset")
                    .shouldBeDetectedAs(new ValueActionFactory<>("HMAC"))
                    .withAnyParameters()
                    .buildForContext(new MacContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> HMAC_CTX_COPY =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("HMAC_CTX_copy")
                    .shouldBeDetectedAs(new ValueActionFactory<>("HMAC"))
                    .withAnyParameters()
                    .buildForContext(new MacContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // HMAC_CTX *HMAC_Init_ex(ctx, key, len, const EVP_MD *md, impl) - md (index 3) is traced back
    // to its EVP_shaXXX()-style constructing call (same mechanism as EVP_PKEY_CTX_SET_HKDF_MD) and
    // surfaces as its own DigestContext finding, separate from the "HMAC" family finding.
    private static final IDetectionRule<AstNode> HMAC_INIT_EX =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("HMAC_Init_ex")
                    .shouldBeDetectedAs(new ValueActionFactory<>("HMAC"))
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .addDependingDetectionRules(OpenSSLEvpMessageDigest.rules())
                    .withMethodParameter("*")
                    .buildForContext(new MacContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // HMAC_CTX *HMAC_Init(ctx, key, len, const EVP_MD *md) - same tracing as HMAC_Init_ex above,
    // md at index 3.
    private static final IDetectionRule<AstNode> HMAC_INIT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("HMAC_Init")
                    .shouldBeDetectedAs(new ValueActionFactory<>("HMAC"))
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .addDependingDetectionRules(OpenSSLEvpMessageDigest.rules())
                    .buildForContext(new MacContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> HMAC_UPDATE =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("HMAC_Update")
                    .shouldBeDetectedAs(new ValueActionFactory<>("HMAC"))
                    .withAnyParameters()
                    .buildForContext(new MacContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> HMAC_FINAL =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("HMAC_Final")
                    .shouldBeDetectedAs(new ValueActionFactory<>("HMAC"))
                    .withAnyParameters()
                    .buildForContext(new MacContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // unsigned char *HMAC(const EVP_MD *evp_md, key, key_len, d, n, md, md_len) - evp_md (index 0)
    // is traced back to its EVP_shaXXX()-style constructing call, same as HMAC_Init_ex/HMAC_Init
    // above.
    private static final IDetectionRule<AstNode> HMAC =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("HMAC")
                    .shouldBeDetectedAs(new ValueActionFactory<>("HMAC"))
                    .withMethodParameter("*")
                    .addDependingDetectionRules(OpenSSLEvpMessageDigest.rules())
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .buildForContext(new MacContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // Legacy CMAC functions
    // ====================================================================

    private static final IDetectionRule<AstNode> CMAC_CTX_NEW =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("CMAC_CTX_new")
                    .shouldBeDetectedAs(new ValueActionFactory<>("CMAC"))
                    .withAnyParameters()
                    .buildForContext(new MacContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // int CMAC_Init(ctx, key, keylen, const EVP_CIPHER *cipher, impl) - cipher (index 3) is
    // traced back to its EVP_aes_128_cbc()-style constructing call and surfaces as its own
    // CipherContext finding, separate from the "CMAC" family finding.
    private static final IDetectionRule<AstNode> CMAC_INIT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("CMAC_Init")
                    .shouldBeDetectedAs(new ValueActionFactory<>("CMAC"))
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .addDependingDetectionRules(OpenSSLEvpCipher.rules())
                    .withMethodParameter("*")
                    .buildForContext(new MacContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> CMAC_UPDATE =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("CMAC_Update")
                    .shouldBeDetectedAs(new ValueActionFactory<>("CMAC"))
                    .withAnyParameters()
                    .buildForContext(new MacContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> CMAC_FINAL =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("CMAC_Final")
                    .shouldBeDetectedAs(new ValueActionFactory<>("CMAC"))
                    .withAnyParameters()
                    .buildForContext(new MacContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> CMAC_RESUME =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("CMAC_resume")
                    .shouldBeDetectedAs(new ValueActionFactory<>("CMAC"))
                    .withAnyParameters()
                    .buildForContext(new MacContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // Note: Poly1305_Init/Update/Final are NOT part of OpenSSL's public API (they live in
    // include/crypto/poly1305.h, not include/openssl/). Public access to Poly1305 in
    // OpenSSL 3.x is via EVP_MAC_fetch(..., "POLY1305", ...), which is covered by
    // OpenSSLEvpMac. Do not add legacy Poly1305_* rules here.

    private OpenSSLLegacyMac() {
        // nothing
    }

    @Nonnull
    public static List<IDetectionRule<AstNode>> rules() {
        return List.of(
                // HMAC
                HMAC_CTX_NEW,
                HMAC_CTX_RESET,
                HMAC_CTX_COPY,
                HMAC_INIT_EX,
                HMAC_INIT,
                HMAC_UPDATE,
                HMAC_FINAL,
                HMAC,
                // CMAC
                CMAC_CTX_NEW,
                CMAC_INIT,
                CMAC_UPDATE,
                CMAC_FINAL,
                CMAC_RESUME);
    }
}
