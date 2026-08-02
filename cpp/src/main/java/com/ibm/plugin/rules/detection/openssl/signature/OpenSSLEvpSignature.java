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

import com.ibm.engine.model.SignatureAction;
import com.ibm.engine.model.context.DigestContext;
import com.ibm.engine.model.context.SignatureContext;
import com.ibm.engine.model.factory.AlgorithmFactory;
import com.ibm.engine.model.factory.SignatureActionFactory;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.plugin.rules.detection.openssl.digest.OpenSSLEvpMessageDigest;
import com.ibm.plugin.rules.detection.openssl.digest.OpenSSLNameCanonicalizerFactory;
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
    // DigestSign / DigestVerify init — the digest argument is traced back to its
    // constructing call (see OpenSSLEvpMessageDigest); the key algorithm (RSA/DSA/ECDSA/SM2)
    // is carried by the EVP_PKEY, which isn't resolvable from this call site.
    // ====================================================================

    private static final IDetectionRule<AstNode> EVP_DIGEST_SIGN_INIT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_DigestSignInit")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .addDependingDetectionRules(OpenSSLEvpMessageDigest.rules())
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_DIGEST_VERIFY_INIT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_DigestVerifyInit")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .addDependingDetectionRules(OpenSSLEvpMessageDigest.rules())
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // Streaming Digest Sign / Verify (init/update/final variants) — SIGN/VERIFY are action
    // markers only (see JcaSignatureAction for the equivalent Java pattern); they carry no key
    // algorithm identity (the EVP_PKEY isn't resolvable from this call site) but *_ex's mdname
    // (index 2) is a real digest-name string (e.g. "SHA256"), resolved via
    // OpenSSLNameCanonicalizerFactory into its own, separate DigestContext finding - same shape
    // as EVP_PKEY_CTX_SET_RSA_MGF1_MD_NAME below.
    // ====================================================================

    private static final IDetectionRule<AstNode> EVP_DIGEST_SIGN_INIT_EX =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_DigestSignInit_ex")
                    .shouldBeDetectedAs(new SignatureActionFactory<>(SignatureAction.Action.SIGN))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_DIGEST_SIGN_INIT_EX_MDNAME =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_DigestSignInit_ex")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(
                            new OpenSSLNameCanonicalizerFactory(
                                    OpenSSLNameCanonicalizerFactory.DIGEST_NAMES))
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .buildForContext(new DigestContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_DIGEST_VERIFY_INIT_EX =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_DigestVerifyInit_ex")
                    .shouldBeDetectedAs(new SignatureActionFactory<>(SignatureAction.Action.VERIFY))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_DIGEST_VERIFY_INIT_EX_MDNAME =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_DigestVerifyInit_ex")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(
                            new OpenSSLNameCanonicalizerFactory(
                                    OpenSSLNameCanonicalizerFactory.DIGEST_NAMES))
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .buildForContext(new DigestContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // EVP_DigestSign / EVP_DigestVerify (one-shot, incl. EdDSA) — action markers only; the
    // key algorithm (e.g. Ed25519/Ed448) is carried by the EVP_PKEY, not this call site.
    // ====================================================================

    private static final IDetectionRule<AstNode> EVP_DIGEST_SIGN =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_DigestSign")
                    .shouldBeDetectedAs(new SignatureActionFactory<>(SignatureAction.Action.SIGN))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_DIGEST_VERIFY =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_DigestVerify")
                    .shouldBeDetectedAs(new SignatureActionFactory<>(SignatureAction.Action.VERIFY))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // EVP_PKEY sign / verify (one-shot, incl. ML-DSA/SLH-DSA) — action markers only; the key
    // algorithm and parameter set are carried by the EVP_PKEY, not this call site.
    // ====================================================================

    private static final IDetectionRule<AstNode> EVP_PKEY_SIGN =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_sign")
                    .shouldBeDetectedAs(new SignatureActionFactory<>(SignatureAction.Action.SIGN))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_PKEY_VERIFY =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_verify")
                    .shouldBeDetectedAs(new SignatureActionFactory<>(SignatureAction.Action.VERIFY))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // EVP_PKEY sign / verify init variants — action markers only.
    // ====================================================================

    private static final IDetectionRule<AstNode> EVP_PKEY_SIGN_INIT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_sign_init")
                    .shouldBeDetectedAs(new SignatureActionFactory<>(SignatureAction.Action.SIGN))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_PKEY_SIGN_INIT_EX =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_sign_init_ex")
                    .shouldBeDetectedAs(new SignatureActionFactory<>(SignatureAction.Action.SIGN))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_PKEY_SIGN_INIT_EX2 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_sign_init_ex2")
                    .shouldBeDetectedAs(new SignatureActionFactory<>(SignatureAction.Action.SIGN))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_PKEY_VERIFY_INIT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_verify_init")
                    .shouldBeDetectedAs(new SignatureActionFactory<>(SignatureAction.Action.VERIFY))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_PKEY_VERIFY_INIT_EX =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_verify_init_ex")
                    .shouldBeDetectedAs(new SignatureActionFactory<>(SignatureAction.Action.VERIFY))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_PKEY_VERIFY_INIT_EX2 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_verify_init_ex2")
                    .shouldBeDetectedAs(new SignatureActionFactory<>(SignatureAction.Action.VERIFY))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // EVP_PKEY message sign / verify (streaming, OpenSSL 3.6) — action markers only.
    // ====================================================================

    private static final IDetectionRule<AstNode> EVP_PKEY_SIGN_MESSAGE_INIT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_sign_message_init")
                    .shouldBeDetectedAs(new SignatureActionFactory<>(SignatureAction.Action.SIGN))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_PKEY_VERIFY_MESSAGE_INIT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_verify_message_init")
                    .shouldBeDetectedAs(new SignatureActionFactory<>(SignatureAction.Action.VERIFY))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // EVP_PKEY verify_recover — action marker only.
    // ====================================================================

    private static final IDetectionRule<AstNode> EVP_PKEY_VERIFY_RECOVER_INIT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_verify_recover_init")
                    .shouldBeDetectedAs(new SignatureActionFactory<>(SignatureAction.Action.VERIFY))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_PKEY_VERIFY_RECOVER_INIT_EX =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_verify_recover_init_ex")
                    .shouldBeDetectedAs(new SignatureActionFactory<>(SignatureAction.Action.VERIFY))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_PKEY_VERIFY_RECOVER_INIT_EX2 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_verify_recover_init_ex2")
                    .shouldBeDetectedAs(new SignatureActionFactory<>(SignatureAction.Action.VERIFY))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // Legacy EVP sign/verify (deprecated 3.0) — action marker only.
    // ====================================================================

    private static final IDetectionRule<AstNode> EVP_VERIFY_INIT_EX =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_VerifyInit_ex")
                    .shouldBeDetectedAs(new SignatureActionFactory<>(SignatureAction.Action.VERIFY))
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
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .withMethodParameter("*")
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
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .addDependingDetectionRules(OpenSSLEvpMessageDigest.rules())
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_PKEY_CTX_SET_RSA_MGF1_MD_NAME =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_CTX_set_rsa_mgf1_md_name")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(
                            new OpenSSLNameCanonicalizerFactory(
                                    OpenSSLNameCanonicalizerFactory.DIGEST_NAMES))
                    .withMethodParameter("*")
                    .buildForContext(new DigestContext())
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
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .addDependingDetectionRules(OpenSSLEvpMessageDigest.rules())
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
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .addDependingDetectionRules(OpenSSLEvpMessageDigest.rules())
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_PKEY_CTX_SET_RSA_PSS_KEYGEN_MD_NAME =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_CTX_set_rsa_pss_keygen_md_name")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(
                            new OpenSSLNameCanonicalizerFactory(
                                    OpenSSLNameCanonicalizerFactory.DIGEST_NAMES))
                    .withMethodParameter("*")
                    .buildForContext(new DigestContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_PKEY_CTX_SET_RSA_PSS_KEYGEN_MGF1_MD =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .addDependingDetectionRules(OpenSSLEvpMessageDigest.rules())
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_PKEY_CTX_SET_RSA_PSS_KEYGEN_MGF1_MD_NAME =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md_name")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(
                            new OpenSSLNameCanonicalizerFactory(
                                    OpenSSLNameCanonicalizerFactory.DIGEST_NAMES))
                    .buildForContext(new DigestContext())
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
                // DigestSign / DigestVerify init (digest traced back; key algorithm not
                // resolvable from this call site)
                EVP_DIGEST_SIGN_INIT,
                EVP_DIGEST_VERIFY_INIT,
                // Streaming Digest Sign/Verify
                EVP_DIGEST_SIGN_INIT_EX,
                EVP_DIGEST_SIGN_INIT_EX_MDNAME,
                EVP_DIGEST_VERIFY_INIT_EX,
                EVP_DIGEST_VERIFY_INIT_EX_MDNAME,
                // EVP_DigestSign / EVP_DigestVerify (one-shot, incl. EdDSA)
                EVP_DIGEST_SIGN,
                EVP_DIGEST_VERIFY,
                // EVP_PKEY sign / verify (one-shot, incl. ML-DSA/SLH-DSA)
                EVP_PKEY_SIGN,
                EVP_PKEY_VERIFY,
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
                CMS_DIGEST_CREATE,
                CMS_DIGEST_CREATE_EX);
    }
}
