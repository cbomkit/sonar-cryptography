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

    // ====================================================================
    // Streaming Digest Sign / Verify (init/update/final variants)
    // ====================================================================

    private static final IDetectionRule<AstNode> EVP_DIGEST_SIGN_INIT_EX =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_DigestSignInit_ex")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SIGN"))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_DIGEST_VERIFY_INIT_EX =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_DigestVerifyInit_ex")
                    .shouldBeDetectedAs(new ValueActionFactory<>("VERIFY"))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // EVP_PKEY sign / verify init variants
    // ====================================================================

    private static final IDetectionRule<AstNode> EVP_PKEY_SIGN_INIT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_sign_init")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SIGN"))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_PKEY_SIGN_INIT_EX =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_sign_init_ex")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SIGN"))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_PKEY_SIGN_INIT_EX2 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_sign_init_ex2")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SIGN"))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_PKEY_VERIFY_INIT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_verify_init")
                    .shouldBeDetectedAs(new ValueActionFactory<>("VERIFY"))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_PKEY_VERIFY_INIT_EX =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_verify_init_ex")
                    .shouldBeDetectedAs(new ValueActionFactory<>("VERIFY"))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_PKEY_VERIFY_INIT_EX2 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_verify_init_ex2")
                    .shouldBeDetectedAs(new ValueActionFactory<>("VERIFY"))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // EVP_PKEY message sign / verify (streaming, OpenSSL 3.6)
    // ====================================================================

    private static final IDetectionRule<AstNode> EVP_PKEY_SIGN_MESSAGE_INIT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_sign_message_init")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SIGN"))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_PKEY_VERIFY_MESSAGE_INIT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_verify_message_init")
                    .shouldBeDetectedAs(new ValueActionFactory<>("VERIFY"))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // EVP_PKEY verify_recover
    // ====================================================================

    private static final IDetectionRule<AstNode> EVP_PKEY_VERIFY_RECOVER_INIT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_verify_recover_init")
                    .shouldBeDetectedAs(new ValueActionFactory<>("VERIFY-RECOVER"))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_PKEY_VERIFY_RECOVER_INIT_EX =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_verify_recover_init_ex")
                    .shouldBeDetectedAs(new ValueActionFactory<>("VERIFY-RECOVER"))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_PKEY_VERIFY_RECOVER_INIT_EX2 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_verify_recover_init_ex2")
                    .shouldBeDetectedAs(new ValueActionFactory<>("VERIFY-RECOVER"))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // Legacy EVP sign/verify (deprecated 3.0)
    // ====================================================================

    private static final IDetectionRule<AstNode> EVP_VERIFY_INIT_EX =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_VerifyInit_ex")
                    .shouldBeDetectedAs(new ValueActionFactory<>("VERIFY"))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // Fetch APIs
    // ====================================================================

    private static final IDetectionRule<AstNode> EVP_SIGNATURE_FETCH =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_SIGNATURE_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SIGNATURE-FETCH"))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // RSA setters (signature-related)
    // ====================================================================

    private static final IDetectionRule<AstNode> EVP_PKEY_CTX_SET_RSA_MGF1_MD =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_CTX_set_rsa_mgf1_md")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RSA-MGF1-MD"))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_PKEY_CTX_SET_RSA_MGF1_MD_NAME =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_CTX_set_rsa_mgf1_md_name")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RSA-MGF1-MD"))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_PKEY_CTX_SET_RSA_PSS_SALTLEN =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_CTX_set_rsa_pss_saltlen")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RSA-PSS-SALTLEN"))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_PKEY_CTX_SET_SIGNATURE_MD =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_CTX_set_signature_md")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SIGNATURE-MD"))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // RSA-PSS keygen-side setters
    // ====================================================================

    private static final IDetectionRule<AstNode> EVP_PKEY_CTX_SET_RSA_PSS_KEYGEN_MD =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_CTX_set_rsa_pss_keygen_md")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RSA-PSS-KEYGEN-MD"))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_PKEY_CTX_SET_RSA_PSS_KEYGEN_MD_NAME =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_CTX_set_rsa_pss_keygen_md_name")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RSA-PSS-KEYGEN-MD"))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_PKEY_CTX_SET_RSA_PSS_KEYGEN_MGF1_MD =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RSA-PSS-KEYGEN-MGF1-MD"))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_PKEY_CTX_SET_RSA_PSS_KEYGEN_MGF1_MD_NAME =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md_name")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RSA-PSS-KEYGEN-MGF1-MD"))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_PKEY_CTX_SET_RSA_PSS_KEYGEN_SALTLEN =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_CTX_set_rsa_pss_keygen_saltlen")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RSA-PSS-KEYGEN-SALTLEN"))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // PKCS7 sign helpers
    // ====================================================================

    private static final IDetectionRule<AstNode> PKCS7_SIGN =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("PKCS7_sign")
                    .shouldBeDetectedAs(new ValueActionFactory<>("PKCS7-SIGN"))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> PKCS7_SIGN_EX =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("PKCS7_sign_ex")
                    .shouldBeDetectedAs(new ValueActionFactory<>("PKCS7-SIGN"))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> PKCS7_SIGN_ADD_SIGNER =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("PKCS7_sign_add_signer")
                    .shouldBeDetectedAs(new ValueActionFactory<>("PKCS7-SIGN"))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> PKCS7_ADD_SIGNATURE =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("PKCS7_add_signature")
                    .shouldBeDetectedAs(new ValueActionFactory<>("PKCS7-SIGN"))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> PKCS7_SET_DIGEST =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("PKCS7_set_digest")
                    .shouldBeDetectedAs(new ValueActionFactory<>("PKCS7-DIGEST"))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // CMS sign helpers
    // ====================================================================

    private static final IDetectionRule<AstNode> CMS_SIGN =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("CMS_sign")
                    .shouldBeDetectedAs(new ValueActionFactory<>("CMS-SIGN"))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> CMS_SIGN_EX =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("CMS_sign_ex")
                    .shouldBeDetectedAs(new ValueActionFactory<>("CMS-SIGN"))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> CMS_SIGN_RECEIPT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("CMS_sign_receipt")
                    .shouldBeDetectedAs(new ValueActionFactory<>("CMS-SIGN"))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> CMS_ADD1_SIGNER =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("CMS_add1_signer")
                    .shouldBeDetectedAs(new ValueActionFactory<>("CMS-SIGN"))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // OCSP signing
    // ====================================================================

    private static final IDetectionRule<AstNode> OCSP_BASIC_SIGN =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("OCSP_basic_sign")
                    .shouldBeDetectedAs(new ValueActionFactory<>("OCSP-SIGN"))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> OCSP_BASIC_SIGN_CTX =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("OCSP_basic_sign_ctx")
                    .shouldBeDetectedAs(new ValueActionFactory<>("OCSP-SIGN"))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> OCSP_REQUEST_SIGN =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("OCSP_request_sign")
                    .shouldBeDetectedAs(new ValueActionFactory<>("OCSP-SIGN"))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // RFC 3161 Timestamp (TS) digest selectors
    // ====================================================================

    private static final IDetectionRule<AstNode> TS_CONF_SET_SIGNER_DIGEST =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("TS_CONF_set_signer_digest")
                    .shouldBeDetectedAs(new ValueActionFactory<>("TS-SIGNER-DIGEST"))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> TS_MSG_IMPRINT_SET_ALGO =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("TS_MSG_IMPRINT_set_algo")
                    .shouldBeDetectedAs(new ValueActionFactory<>("TS-IMPRINT-ALGO"))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> TS_RESP_CTX_ADD_MD =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("TS_RESP_CTX_add_md")
                    .shouldBeDetectedAs(new ValueActionFactory<>("TS-MD"))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> TS_RESP_CTX_SET_SIGNER_DIGEST =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("TS_RESP_CTX_set_signer_digest")
                    .shouldBeDetectedAs(new ValueActionFactory<>("TS-SIGNER-DIGEST"))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> OSSL_CRMF_PBM_NEW =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("OSSL_CRMF_pbm_new")
                    .shouldBeDetectedAs(new ValueActionFactory<>("CRMF-PBM"))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> OSSL_CRMF_MSG_CREATE_POPO =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("OSSL_CRMF_MSG_create_popo")
                    .shouldBeDetectedAs(new ValueActionFactory<>("CRMF-POPO"))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_DIGEST_SIGN_INIT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_DigestSignInit")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SIGN"))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_DIGEST_VERIFY_INIT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_DigestVerifyInit")
                    .shouldBeDetectedAs(new ValueActionFactory<>("VERIFY"))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> CMS_DIGEST_CREATE =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("CMS_digest_create")
                    .shouldBeDetectedAs(new ValueActionFactory<>("CMS-DIGEST-SIGN"))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> CMS_DIGEST_CREATE_EX =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("CMS_digest_create_ex")
                    .shouldBeDetectedAs(new ValueActionFactory<>("CMS-DIGEST-SIGN"))
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
                SM2,
                // Streaming Digest Sign/Verify
                EVP_DIGEST_SIGN_INIT_EX,
                EVP_DIGEST_VERIFY_INIT_EX,
                // EVP_PKEY sign/verify init
                EVP_PKEY_SIGN_INIT,
                EVP_PKEY_SIGN_INIT_EX,
                EVP_PKEY_SIGN_INIT_EX2,
                EVP_PKEY_VERIFY_INIT,
                EVP_PKEY_VERIFY_INIT_EX,
                EVP_PKEY_VERIFY_INIT_EX2,
                // EVP_PKEY message sign/verify
                EVP_PKEY_SIGN_MESSAGE_INIT,
                EVP_PKEY_VERIFY_MESSAGE_INIT,
                // EVP_PKEY verify_recover
                EVP_PKEY_VERIFY_RECOVER_INIT,
                EVP_PKEY_VERIFY_RECOVER_INIT_EX,
                EVP_PKEY_VERIFY_RECOVER_INIT_EX2,
                // Legacy EVP sign/verify (deprecated 3.0)
                EVP_VERIFY_INIT_EX,
                // Fetch
                EVP_SIGNATURE_FETCH,
                // RSA setters
                EVP_PKEY_CTX_SET_RSA_MGF1_MD,
                EVP_PKEY_CTX_SET_RSA_MGF1_MD_NAME,
                EVP_PKEY_CTX_SET_RSA_PSS_SALTLEN,
                EVP_PKEY_CTX_SET_SIGNATURE_MD,
                // RSA-PSS keygen-side setters
                EVP_PKEY_CTX_SET_RSA_PSS_KEYGEN_MD,
                EVP_PKEY_CTX_SET_RSA_PSS_KEYGEN_MD_NAME,
                EVP_PKEY_CTX_SET_RSA_PSS_KEYGEN_MGF1_MD,
                EVP_PKEY_CTX_SET_RSA_PSS_KEYGEN_MGF1_MD_NAME,
                EVP_PKEY_CTX_SET_RSA_PSS_KEYGEN_SALTLEN,
                // PKCS7 sign
                PKCS7_SIGN,
                PKCS7_SIGN_EX,
                PKCS7_SIGN_ADD_SIGNER,
                PKCS7_ADD_SIGNATURE,
                PKCS7_SET_DIGEST,
                // CMS sign
                CMS_SIGN,
                CMS_SIGN_EX,
                CMS_SIGN_RECEIPT,
                CMS_ADD1_SIGNER,
                // OCSP
                OCSP_BASIC_SIGN,
                OCSP_BASIC_SIGN_CTX,
                OCSP_REQUEST_SIGN,
                // RFC 3161 TS
                TS_CONF_SET_SIGNER_DIGEST,
                TS_MSG_IMPRINT_SET_ALGO,
                TS_RESP_CTX_ADD_MD,
                TS_RESP_CTX_SET_SIGNER_DIGEST,
                // CMP/CRMF
                OSSL_CRMF_PBM_NEW,
                OSSL_CRMF_MSG_CREATE_POPO,
                // New additions
                EVP_DIGEST_SIGN_INIT,
                EVP_DIGEST_VERIFY_INIT,
                CMS_DIGEST_CREATE,
                CMS_DIGEST_CREATE_EX);
    }
}
