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
package com.ibm.plugin.rules.detection.openssl.keyagreement;

import com.ibm.engine.language.cxx.CxxLanguageTranslation;
import com.ibm.engine.model.context.KeyAgreementContext;
import com.ibm.engine.model.context.KeyDerivationFunctionContext;
import com.ibm.engine.model.factory.AlgorithmFactory;
import com.ibm.engine.rule.DetectionRuleSet;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.RuleSets;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.plugin.rules.detection.openssl.digest.OpenSSLEvpMessageDigest;
import com.ibm.plugin.rules.detection.openssl.legacy.OpenSSLNidLookupFactory;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.List;
import java.util.Map;
import javax.annotation.Nonnull;

/**
 * Detection rules for OpenSSL key agreement and key encapsulation.
 *
 * <ul>
 *   <li>{@code EVP_KEYEXCH_fetch} and {@code EVP_KEM_fetch} select a key exchange (DH, ECDH,
 *       X25519, X448) or a key encapsulation mechanism (RSA, EC, X25519, X448, ML-KEM and the
 *       hybrid ML-KEM groups) by name.
 *   <li>{@code EVP_PKEY_CTX_set_ecdh_kdf_type} and {@code EVP_PKEY_CTX_set_dh_kdf_type} select the
 *       KDF applied to the shared secret of an ECDH (ANSI X9.63) or DH (ANSI X9.42) derivation. Its
 *       digest is set on the same context:
 *       <pre>{@code
 * EVP_PKEY_CTX_set_ecdh_kdf_type(ctx, EVP_PKEY_ECDH_KDF_X9_63);
 * EVP_PKEY_CTX_set_ecdh_kdf_md(ctx, EVP_sha256());
 * }</pre>
 *   <li>The HPKE (RFC 9180) functions take the suite, the KEM, KDF and AEAD, as a string ({@code
 *       OSSL_HPKE_str2suite}) or as an {@code OSSL_HPKE_SUITE} ({@code OSSL_HPKE_CTX_new}, {@code
 *       OSSL_HPKE_keygen}).
 * </ul>
 *
 * The key type of an {@code EVP_PKEY_derive} or {@code EVP_PKEY_encapsulate} context comes from a
 * key created elsewhere, so the derivation and encapsulation calls themselves are not reported.
 */
@SuppressWarnings("java:S1192")
public final class OpenSSLEvpKeyAgreement extends DetectionRuleSet<AstNode> {

    private static final String BUNDLE = "OpenSSL";

    // Key exchange and KEM fetch

    private static final IDetectionRule<AstNode> EVP_KEYEXCH_FETCH =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                    .forMethods("EVP_KEYEXCH_fetch")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .withMethodParameter("*")
                    .buildForContext(new KeyAgreementContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_KEM_FETCH =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                    .forMethods("EVP_KEM_fetch")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .withMethodParameter("*")
                    .buildForContext(new KeyAgreementContext(Map.of("kind", "KEM")))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // KDF applied to the shared secret of an ECDH or DH derivation, with the digest set on the
    // same context

    private static final IDetectionRule<AstNode> EVP_PKEY_CTX_SET_ECDH_KDF_MD =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                    .forMethods("EVP_PKEY_CTX_set_ecdh_kdf_md")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .addDependingDetectionRules(RuleSets.rulesOf(OpenSSLEvpMessageDigest.class))
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_PKEY_CTX_SET_ECDH_KDF_TYPE =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                    .forMethods("EVP_PKEY_CTX_set_ecdh_kdf_type")
                    .withMethodParameter("*")
                    .addDependingDetectionRules(List.of(EVP_PKEY_CTX_SET_ECDH_KDF_MD))
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(
                            new OpenSSLNidLookupFactory(
                                    OpenSSLNidLookupFactory.ECDH_KDF_TYPE_BY_CODE,
                                    OpenSSLNidLookupFactory.ECDH_KDF_TYPE_BY_NAME))
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_PKEY_CTX_SET_DH_KDF_MD =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                    .forMethods("EVP_PKEY_CTX_set_dh_kdf_md")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .addDependingDetectionRules(RuleSets.rulesOf(OpenSSLEvpMessageDigest.class))
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_PKEY_CTX_SET_DH_KDF_TYPE =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                    .forMethods("EVP_PKEY_CTX_set_dh_kdf_type")
                    .withMethodParameter("*")
                    .addDependingDetectionRules(List.of(EVP_PKEY_CTX_SET_DH_KDF_MD))
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(
                            new OpenSSLNidLookupFactory(
                                    OpenSSLNidLookupFactory.DH_KDF_TYPE_BY_CODE,
                                    OpenSSLNidLookupFactory.DH_KDF_TYPE_BY_NAME))
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // HPKE (Hybrid Public Key Encryption, RFC 9180)

    private static final IDetectionRule<AstNode> OSSL_HPKE_STR2SUITE =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                    .forMethods("OSSL_HPKE_str2suite")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(new OpenSSLHpkeSuiteFactory())
                    .withMethodParameter("*")
                    .buildForContext(new KeyAgreementContext(Map.of("kind", "HPKE")))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // OSSL_HPKE_CTX_new(mode, suite, role, libctx, propq)
    private static final IDetectionRule<AstNode> OSSL_HPKE_CTX_NEW =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                    .forMethods("OSSL_HPKE_CTX_new")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(new OpenSSLHpkeSuiteFactory())
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .buildForContext(new KeyAgreementContext(Map.of("kind", "HPKE")))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // OSSL_HPKE_keygen(suite, pub, publen, priv, ikm, ikmlen, libctx, propq)
    private static final IDetectionRule<AstNode> OSSL_HPKE_KEYGEN =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                    .forMethods("OSSL_HPKE_keygen")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(new OpenSSLHpkeSuiteFactory())
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .buildForContext(new KeyAgreementContext(Map.of("kind", "HPKE")))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    @Nonnull
    @Override
    protected List<IDetectionRule<AstNode>> buildRules() {
        return List.of(
                // Key exchange and KEM fetch
                EVP_KEYEXCH_FETCH,
                EVP_KEM_FETCH,
                // KDF of an ECDH or DH derivation
                EVP_PKEY_CTX_SET_ECDH_KDF_TYPE,
                EVP_PKEY_CTX_SET_DH_KDF_TYPE,
                // HPKE
                OSSL_HPKE_STR2SUITE,
                OSSL_HPKE_CTX_NEW,
                OSSL_HPKE_KEYGEN);
    }
}
