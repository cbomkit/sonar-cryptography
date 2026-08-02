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

import com.ibm.engine.model.context.KeyAgreementContext;
import com.ibm.engine.model.factory.AlgorithmFactory;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.plugin.rules.detection.openssl.digest.OpenSSLEvpMessageDigest;
import com.ibm.plugin.rules.detection.openssl.legacy.OpenSSLNidLookupFactory;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.List;
import java.util.Map;
import javax.annotation.Nonnull;

/**
 * Detection rules for OpenSSL key agreement operations.
 *
 * <p>These rules detect key agreement/exchange operations through EVP_PKEY_derive and related
 * functions. Covers Diffie-Hellman (DH), Elliptic Curve Diffie-Hellman (ECDH), X25519/X448,
 * post-quantum ML-KEM (Kyber), and SM2.
 */
@SuppressWarnings("java:S1192")
public final class OpenSSLEvpKeyAgreement {

    private static final String BUNDLE = "OpenSSL";

    // ====================================================================
    // KEM / KEYEXCH fetch
    // ====================================================================

    private static final IDetectionRule<AstNode> EVP_KEYEXCH_FETCH =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_KEYEXCH_fetch")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .withMethodParameter("*")
                    .buildForContext(new KeyAgreementContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // EVP_PKEY derive init
    // ====================================================================

    private static final IDetectionRule<AstNode> EVP_PKEY_DERIVE_INIT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_derive_init")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DERIVE"))
                    .withAnyParameters()
                    .buildForContext(new KeyAgreementContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_PKEY_DERIVE_INIT_EX =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_derive_init_ex")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DERIVE"))
                    .withAnyParameters()
                    .buildForContext(new KeyAgreementContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // ECDH / DH KDF setters
    // ====================================================================

    private static final IDetectionRule<AstNode> EVP_PKEY_CTX_SET_DH_KDF_TYPE =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_CTX_set_dh_kdf_type")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DH-KDF-TYPE"))
                    .withAnyParameters()
                    .buildForContext(new KeyAgreementContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_PKEY_CTX_SET_DH_KDF_MD =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_CTX_set_dh_kdf_md")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .addDependingDetectionRules(OpenSSLEvpMessageDigest.rules())
                    .buildForContext(new KeyAgreementContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_PKEY_CTX_SET_ECDH_KDF_TYPE =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_CTX_set_ecdh_kdf_type")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ECDH-KDF-TYPE"))
                    .withAnyParameters()
                    .buildForContext(new KeyAgreementContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_PKEY_CTX_SET_ECDH_KDF_MD =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_CTX_set_ecdh_kdf_md")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .addDependingDetectionRules(OpenSSLEvpMessageDigest.rules())
                    .buildForContext(new KeyAgreementContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // DH parameter setters
    // ====================================================================

    private static final IDetectionRule<AstNode> EVP_PKEY_CTX_SET_DH_PARAMGEN =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods(
                            "EVP_PKEY_CTX_set_dh_paramgen_prime_len",
                            "EVP_PKEY_CTX_set_dh_paramgen_generator",
                            "EVP_PKEY_CTX_set_dh_paramgen_type",
                            "EVP_PKEY_CTX_set_dh_paramgen_subprime_len")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DH-PARAMGEN"))
                    .withAnyParameters()
                    .buildForContext(new KeyAgreementContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_PKEY_CTX_SET_DH_NID =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_CTX_set_dh_nid")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(
                            new OpenSSLNidLookupFactory(
                                    OpenSSLNidLookupFactory.DH_GROUP_BY_CODE, Map.of()))
                    .buildForContext(new KeyAgreementContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_PKEY_CTX_SET_DH_RFC5114 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_CTX_set_dh_rfc5114")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DH-RFC5114"))
                    .withAnyParameters()
                    .buildForContext(new KeyAgreementContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_PKEY_CTX_SET_DHX_RFC5114 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_CTX_set_dhx_rfc5114")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DHX-RFC5114"))
                    .withAnyParameters()
                    .buildForContext(new KeyAgreementContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // KEM fetch
    // ====================================================================

    private static final IDetectionRule<AstNode> EVP_KEM_FETCH =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_KEM_fetch")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .withMethodParameter("*")
                    .buildForContext(new KeyAgreementContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // EVP_PKEY encapsulate / decapsulate
    // ====================================================================

    private static final IDetectionRule<AstNode> EVP_PKEY_ENCAPSULATE_INIT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_encapsulate_init")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ENCAPSULATE"))
                    .withAnyParameters()
                    .buildForContext(new KeyAgreementContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_PKEY_ENCAPSULATE =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_encapsulate")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ENCAPSULATE"))
                    .withAnyParameters()
                    .buildForContext(new KeyAgreementContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_PKEY_DECAPSULATE_INIT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_decapsulate_init")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DECAPSULATE"))
                    .withAnyParameters()
                    .buildForContext(new KeyAgreementContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_PKEY_DECAPSULATE =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_decapsulate")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DECAPSULATE"))
                    .withAnyParameters()
                    .buildForContext(new KeyAgreementContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_PKEY_AUTH_ENCAPSULATE_INIT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_auth_encapsulate_init")
                    .shouldBeDetectedAs(new ValueActionFactory<>("AUTH-ENCAPSULATE"))
                    .withAnyParameters()
                    .buildForContext(new KeyAgreementContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_PKEY_AUTH_DECAPSULATE_INIT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_auth_decapsulate_init")
                    .shouldBeDetectedAs(new ValueActionFactory<>("AUTH-DECAPSULATE"))
                    .withAnyParameters()
                    .buildForContext(new KeyAgreementContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // HPKE (Hybrid Public Key Encryption)
    // ====================================================================

    private static final IDetectionRule<AstNode> OSSL_HPKE_CTX_LIFECYCLE =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("OSSL_HPKE_CTX_new", "OSSL_HPKE_keygen")
                    .shouldBeDetectedAs(new ValueActionFactory<>("HPKE"))
                    .withAnyParameters()
                    .buildForContext(new KeyAgreementContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> OSSL_HPKE_STR2SUITE =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("OSSL_HPKE_str2suite")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .withMethodParameter("*")
                    .buildForContext(new KeyAgreementContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private OpenSSLEvpKeyAgreement() {
        // nothing
    }

    @Nonnull
    public static List<IDetectionRule<AstNode>> rules() {
        return List.of(
                // KEM / KEYEXCH fetch
                EVP_KEYEXCH_FETCH,
                // EVP_PKEY derive init
                EVP_PKEY_DERIVE_INIT,
                EVP_PKEY_DERIVE_INIT_EX,
                // ECDH / DH KDF setters
                EVP_PKEY_CTX_SET_DH_KDF_TYPE,
                EVP_PKEY_CTX_SET_DH_KDF_MD,
                EVP_PKEY_CTX_SET_ECDH_KDF_TYPE,
                EVP_PKEY_CTX_SET_ECDH_KDF_MD,
                // DH parameter setters
                EVP_PKEY_CTX_SET_DH_PARAMGEN,
                EVP_PKEY_CTX_SET_DH_NID,
                EVP_PKEY_CTX_SET_DH_RFC5114,
                EVP_PKEY_CTX_SET_DHX_RFC5114,
                // KEM fetch
                EVP_KEM_FETCH,
                // EVP_PKEY encapsulate
                EVP_PKEY_ENCAPSULATE_INIT,
                EVP_PKEY_ENCAPSULATE,
                // EVP_PKEY decapsulate
                EVP_PKEY_DECAPSULATE_INIT,
                EVP_PKEY_DECAPSULATE,
                // Authenticated KEM variants
                EVP_PKEY_AUTH_ENCAPSULATE_INIT,
                EVP_PKEY_AUTH_DECAPSULATE_INIT,
                // HPKE
                OSSL_HPKE_CTX_LIFECYCLE,
                OSSL_HPKE_STR2SUITE);
    }
}
