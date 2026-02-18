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
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.List;
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
    // Diffie-Hellman (DH)
    // ====================================================================

    private static final IDetectionRule<AstNode> DH_DERIVE =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_derive")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DH"))
                    .withAnyParameters()
                    .buildForContext(new KeyAgreementContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> DH_2048 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_CTX_new_id")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DH-2048"))
                    .withMethodParameter("EVP_PKEY_DH")
                    .buildForContext(new KeyAgreementContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> DH_3072 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_CTX_new_id")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DH-3072"))
                    .withMethodParameter("EVP_PKEY_DH")
                    .buildForContext(new KeyAgreementContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> DH_4096 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_CTX_new_id")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DH-4096"))
                    .withMethodParameter("EVP_PKEY_DH")
                    .buildForContext(new KeyAgreementContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // Elliptic Curve Diffie-Hellman (ECDH)
    // ====================================================================

    private static final IDetectionRule<AstNode> ECDH_DERIVE =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_derive")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ECDH"))
                    .withAnyParameters()
                    .buildForContext(new KeyAgreementContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> ECDH_P256 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_CTX_new_id")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ECDH-P256"))
                    .withMethodParameter("EVP_PKEY_EC")
                    .buildForContext(new KeyAgreementContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> ECDH_P384 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_CTX_new_id")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ECDH-P384"))
                    .withMethodParameter("EVP_PKEY_EC")
                    .buildForContext(new KeyAgreementContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> ECDH_P521 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_CTX_new_id")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ECDH-P521"))
                    .withMethodParameter("EVP_PKEY_EC")
                    .buildForContext(new KeyAgreementContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> ECDH_SECP256K1 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_CTX_new_id")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ECDH-SECP256K1"))
                    .withMethodParameter("EVP_PKEY_EC")
                    .buildForContext(new KeyAgreementContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> ECDH_BRAINPOOLP256R1 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_CTX_new_id")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ECDH-BRAINPOOLP256R1"))
                    .withMethodParameter("EVP_PKEY_EC")
                    .buildForContext(new KeyAgreementContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> ECDH_BRAINPOOLP384R1 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_CTX_new_id")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ECDH-BRAINPOOLP384R1"))
                    .withMethodParameter("EVP_PKEY_EC")
                    .buildForContext(new KeyAgreementContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> ECDH_BRAINPOOLP512R1 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_CTX_new_id")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ECDH-BRAINPOOLP512R1"))
                    .withMethodParameter("EVP_PKEY_EC")
                    .buildForContext(new KeyAgreementContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // X25519 and X448 - Modern Curve25519/Curve448 key exchange
    // ====================================================================

    private static final IDetectionRule<AstNode> X25519_DERIVE =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_derive")
                    .shouldBeDetectedAs(new ValueActionFactory<>("X25519"))
                    .withAnyParameters()
                    .buildForContext(new KeyAgreementContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> X25519_CTX =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_CTX_new_id")
                    .shouldBeDetectedAs(new ValueActionFactory<>("X25519"))
                    .withMethodParameter("EVP_PKEY_X25519")
                    .buildForContext(new KeyAgreementContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> X448_DERIVE =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_derive")
                    .shouldBeDetectedAs(new ValueActionFactory<>("X448"))
                    .withAnyParameters()
                    .buildForContext(new KeyAgreementContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> X448_CTX =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_CTX_new_id")
                    .shouldBeDetectedAs(new ValueActionFactory<>("X448"))
                    .withMethodParameter("EVP_PKEY_X448")
                    .buildForContext(new KeyAgreementContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // ML-KEM (Kyber) - Post-Quantum Key Encapsulation Mechanism
    // ====================================================================

    private static final IDetectionRule<AstNode> ML_KEM_512_ENCAPS =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_encapsulate")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ML-KEM-512"))
                    .withAnyParameters()
                    .buildForContext(new KeyAgreementContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> ML_KEM_512_DECAPS =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_decapsulate")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ML-KEM-512"))
                    .withAnyParameters()
                    .buildForContext(new KeyAgreementContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> ML_KEM_768_ENCAPS =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_encapsulate")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ML-KEM-768"))
                    .withAnyParameters()
                    .buildForContext(new KeyAgreementContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> ML_KEM_768_DECAPS =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_decapsulate")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ML-KEM-768"))
                    .withAnyParameters()
                    .buildForContext(new KeyAgreementContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> ML_KEM_1024_ENCAPS =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_encapsulate")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ML-KEM-1024"))
                    .withAnyParameters()
                    .buildForContext(new KeyAgreementContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> ML_KEM_1024_DECAPS =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_decapsulate")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ML-KEM-1024"))
                    .withAnyParameters()
                    .buildForContext(new KeyAgreementContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // Hybrid Post-Quantum KEMs (PQC + Classical)
    // ====================================================================

    // X25519MLKEM768 - X25519 + ML-KEM-768 (TLS group 0x11EC)
    private static final IDetectionRule<AstNode> X25519MLKEM768_ENCAPS =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_encapsulate")
                    .shouldBeDetectedAs(new ValueActionFactory<>("X25519MLKEM768"))
                    .withAnyParameters()
                    .buildForContext(new KeyAgreementContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> X25519MLKEM768_DECAPS =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_decapsulate")
                    .shouldBeDetectedAs(new ValueActionFactory<>("X25519MLKEM768"))
                    .withAnyParameters()
                    .buildForContext(new KeyAgreementContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // X448MLKEM1024 - X448 + ML-KEM-1024 (TLS group 0x11EE)
    private static final IDetectionRule<AstNode> X448MLKEM1024_ENCAPS =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_encapsulate")
                    .shouldBeDetectedAs(new ValueActionFactory<>("X448MLKEM1024"))
                    .withAnyParameters()
                    .buildForContext(new KeyAgreementContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> X448MLKEM1024_DECAPS =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_decapsulate")
                    .shouldBeDetectedAs(new ValueActionFactory<>("X448MLKEM1024"))
                    .withAnyParameters()
                    .buildForContext(new KeyAgreementContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // SecP256r1MLKEM768 - ECDH P-256 + ML-KEM-768 (TLS group 0x11EB)
    private static final IDetectionRule<AstNode> SECP256R1MLKEM768_ENCAPS =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_encapsulate")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SecP256r1MLKEM768"))
                    .withAnyParameters()
                    .buildForContext(new KeyAgreementContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> SECP256R1MLKEM768_DECAPS =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_decapsulate")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SecP256r1MLKEM768"))
                    .withAnyParameters()
                    .buildForContext(new KeyAgreementContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // SecP384r1MLKEM1024 - ECDH P-384 + ML-KEM-1024 (TLS group 0x11ED)
    private static final IDetectionRule<AstNode> SECP384R1MLKEM1024_ENCAPS =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_encapsulate")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SecP384r1MLKEM1024"))
                    .withAnyParameters()
                    .buildForContext(new KeyAgreementContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> SECP384R1MLKEM1024_DECAPS =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_decapsulate")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SecP384r1MLKEM1024"))
                    .withAnyParameters()
                    .buildForContext(new KeyAgreementContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // SM2 Key Exchange
    // ====================================================================

    private static final IDetectionRule<AstNode> SM2_DERIVE =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_derive")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SM2"))
                    .withAnyParameters()
                    .buildForContext(new KeyAgreementContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private OpenSSLEvpKeyAgreement() {
        // nothing
    }

    @Nonnull
    public static List<IDetectionRule<AstNode>> rules() {
        return List.of(
                // DH
                DH_DERIVE,
                DH_2048,
                DH_3072,
                DH_4096,
                // ECDH
                ECDH_DERIVE,
                ECDH_P256,
                ECDH_P384,
                ECDH_P521,
                ECDH_SECP256K1,
                ECDH_BRAINPOOLP256R1,
                ECDH_BRAINPOOLP384R1,
                ECDH_BRAINPOOLP512R1,
                // X25519/X448
                X25519_DERIVE,
                X25519_CTX,
                X448_DERIVE,
                X448_CTX,
                // ML-KEM (Post-Quantum)
                ML_KEM_512_ENCAPS,
                ML_KEM_512_DECAPS,
                ML_KEM_768_ENCAPS,
                ML_KEM_768_DECAPS,
                ML_KEM_1024_ENCAPS,
                ML_KEM_1024_DECAPS,
                // Hybrid PQC KEMs
                X25519MLKEM768_ENCAPS,
                X25519MLKEM768_DECAPS,
                X448MLKEM1024_ENCAPS,
                X448MLKEM1024_DECAPS,
                SECP256R1MLKEM768_ENCAPS,
                SECP256R1MLKEM768_DECAPS,
                SECP384R1MLKEM1024_ENCAPS,
                SECP384R1MLKEM1024_DECAPS,
                // SM2
                SM2_DERIVE);
    }
}
