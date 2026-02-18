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
package com.ibm.plugin.rules.detection.openssl.signature;

import com.ibm.engine.model.context.SignatureContext;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.List;
import javax.annotation.Nonnull;

/**
 * Detection rules for OpenSSL signature operations.
 *
 * <p>These rules detect signature algorithm usage through EVP_DigestSign/Verify operations and
 * EVP_PKEY operations that specify signature algorithms.
 *
 * <p>Covers RSA (PKCS#1 v1.5, PSS), DSA, ECDSA, EdDSA, post-quantum (ML-DSA, SLH-DSA), and SM2
 * signatures.
 */
@SuppressWarnings("java:S1192")
public final class OpenSSLEvpSignature {

    private static final String BUNDLE = "OpenSSL";

    // ====================================================================
    // RSA Signatures - PKCS#1 v1.5
    // ====================================================================

    private static final IDetectionRule<AstNode> RSA_PKCS1_SHA1 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_DigestSignInit", "EVP_DigestVerifyInit")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RSA-SHA1"))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> RSA_PKCS1_SHA224 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_DigestSignInit", "EVP_DigestVerifyInit")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RSA-SHA224"))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> RSA_PKCS1_SHA256 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_DigestSignInit", "EVP_DigestVerifyInit")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RSA-SHA256"))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> RSA_PKCS1_SHA384 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_DigestSignInit", "EVP_DigestVerifyInit")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RSA-SHA384"))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> RSA_PKCS1_SHA512 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_DigestSignInit", "EVP_DigestVerifyInit")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RSA-SHA512"))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // RSA Signatures - PSS
    // ====================================================================

    private static final IDetectionRule<AstNode> RSA_PSS_SHA256 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_CTX_set_rsa_padding")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RSA-PSS-SHA256"))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> RSA_PSS_SHA384 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_CTX_set_rsa_padding")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RSA-PSS-SHA384"))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> RSA_PSS_SHA512 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_CTX_set_rsa_padding")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RSA-PSS-SHA512"))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // DSA Signatures
    // ====================================================================

    private static final IDetectionRule<AstNode> DSA_SHA1 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_DigestSignInit", "EVP_DigestVerifyInit")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DSA-SHA1"))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> DSA_SHA224 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_DigestSignInit", "EVP_DigestVerifyInit")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DSA-SHA224"))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> DSA_SHA256 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_DigestSignInit", "EVP_DigestVerifyInit")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DSA-SHA256"))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> DSA_SHA384 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_DigestSignInit", "EVP_DigestVerifyInit")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DSA-SHA384"))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> DSA_SHA512 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_DigestSignInit", "EVP_DigestVerifyInit")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DSA-SHA512"))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // ECDSA Signatures
    // ====================================================================

    private static final IDetectionRule<AstNode> ECDSA_SHA1 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_DigestSignInit", "EVP_DigestVerifyInit")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ECDSA-SHA1"))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> ECDSA_SHA224 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_DigestSignInit", "EVP_DigestVerifyInit")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ECDSA-SHA224"))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> ECDSA_SHA256 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_DigestSignInit", "EVP_DigestVerifyInit")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ECDSA-SHA256"))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> ECDSA_SHA384 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_DigestSignInit", "EVP_DigestVerifyInit")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ECDSA-SHA384"))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> ECDSA_SHA512 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_DigestSignInit", "EVP_DigestVerifyInit")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ECDSA-SHA512"))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> ECDSA_SHA3_256 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_DigestSignInit", "EVP_DigestVerifyInit")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ECDSA-SHA3-256"))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> ECDSA_SHA3_384 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_DigestSignInit", "EVP_DigestVerifyInit")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ECDSA-SHA3-384"))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> ECDSA_SHA3_512 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_DigestSignInit", "EVP_DigestVerifyInit")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ECDSA-SHA3-512"))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // EdDSA Signatures
    // ====================================================================

    private static final IDetectionRule<AstNode> ED25519 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_DigestSign", "EVP_DigestVerify")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ED25519"))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> ED448 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_DigestSign", "EVP_DigestVerify")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ED448"))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // Post-Quantum Signatures - ML-DSA
    // ====================================================================

    private static final IDetectionRule<AstNode> ML_DSA_44 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_sign", "EVP_PKEY_verify")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ML-DSA-44"))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> ML_DSA_65 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_sign", "EVP_PKEY_verify")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ML-DSA-65"))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> ML_DSA_87 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_sign", "EVP_PKEY_verify")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ML-DSA-87"))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // Post-Quantum Signatures - SLH-DSA
    // ====================================================================

    private static final IDetectionRule<AstNode> SLH_DSA_SHA2_128F =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_sign", "EVP_PKEY_verify")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SLH-DSA-SHA2-128F"))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> SLH_DSA_SHA2_128S =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_sign", "EVP_PKEY_verify")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SLH-DSA-SHA2-128S"))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> SLH_DSA_SHAKE_128F =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_sign", "EVP_PKEY_verify")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SLH-DSA-SHAKE-128F"))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> SLH_DSA_SHAKE_128S =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_sign", "EVP_PKEY_verify")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SLH-DSA-SHAKE-128S"))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> SLH_DSA_SHA2_192F =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_sign", "EVP_PKEY_verify")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SLH-DSA-SHA2-192F"))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> SLH_DSA_SHA2_192S =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_sign", "EVP_PKEY_verify")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SLH-DSA-SHA2-192S"))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> SLH_DSA_SHAKE_192F =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_sign", "EVP_PKEY_verify")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SLH-DSA-SHAKE-192F"))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> SLH_DSA_SHAKE_192S =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_sign", "EVP_PKEY_verify")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SLH-DSA-SHAKE-192S"))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> SLH_DSA_SHA2_256F =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_sign", "EVP_PKEY_verify")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SLH-DSA-SHA2-256F"))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> SLH_DSA_SHA2_256S =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_sign", "EVP_PKEY_verify")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SLH-DSA-SHA2-256S"))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> SLH_DSA_SHAKE_256F =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_sign", "EVP_PKEY_verify")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SLH-DSA-SHAKE-256F"))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> SLH_DSA_SHAKE_256S =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_sign", "EVP_PKEY_verify")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SLH-DSA-SHAKE-256S"))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // SM2 Signature
    // ====================================================================

    private static final IDetectionRule<AstNode> SM2 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_DigestSignInit", "EVP_DigestVerifyInit")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SM2"))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private OpenSSLEvpSignature() {
        // nothing
    }

    @Nonnull
    public static List<IDetectionRule<AstNode>> rules() {
        return List.of(
                // RSA PKCS#1 v1.5
                RSA_PKCS1_SHA1,
                RSA_PKCS1_SHA224,
                RSA_PKCS1_SHA256,
                RSA_PKCS1_SHA384,
                RSA_PKCS1_SHA512,
                // RSA-PSS
                RSA_PSS_SHA256,
                RSA_PSS_SHA384,
                RSA_PSS_SHA512,
                // DSA
                DSA_SHA1,
                DSA_SHA224,
                DSA_SHA256,
                DSA_SHA384,
                DSA_SHA512,
                // ECDSA
                ECDSA_SHA1,
                ECDSA_SHA224,
                ECDSA_SHA256,
                ECDSA_SHA384,
                ECDSA_SHA512,
                ECDSA_SHA3_256,
                ECDSA_SHA3_384,
                ECDSA_SHA3_512,
                // EdDSA
                ED25519,
                ED448,
                // ML-DSA (Post-Quantum)
                ML_DSA_44,
                ML_DSA_65,
                ML_DSA_87,
                // SLH-DSA (Post-Quantum)
                SLH_DSA_SHA2_128F,
                SLH_DSA_SHA2_128S,
                SLH_DSA_SHAKE_128F,
                SLH_DSA_SHAKE_128S,
                SLH_DSA_SHA2_192F,
                SLH_DSA_SHA2_192S,
                SLH_DSA_SHAKE_192F,
                SLH_DSA_SHAKE_192S,
                SLH_DSA_SHA2_256F,
                SLH_DSA_SHA2_256S,
                SLH_DSA_SHAKE_256F,
                SLH_DSA_SHAKE_256S,
                // SM2
                SM2);
    }
}
