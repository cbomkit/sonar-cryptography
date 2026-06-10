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
package com.ibm.plugin.rules.detection.openssl.keygen;

import com.ibm.engine.model.context.KeyContext;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.List;
import javax.annotation.Nonnull;

@SuppressWarnings("java:S1192")
public final class OpenSSLEvpKeyGen {

    private static final String BUNDLE = "OpenSSL";

    // ====================================================================
    // RSA Key Generation
    // ====================================================================

    private static final IDetectionRule<AstNode> EVP_PKEY_CTX_NEW_RSA =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_CTX_new_id")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RSA"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(KeyContext.Kind.NONE))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_PKEY_CTX_NEW_RSA_PSS =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_CTX_new_id")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RSA-PSS"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(KeyContext.Kind.NONE))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_RSA_KEYGEN_BITS_2048 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_CTX_set_rsa_keygen_bits")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RSA-2048"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(KeyContext.Kind.NONE))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_RSA_KEYGEN_BITS_3072 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_CTX_set_rsa_keygen_bits")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RSA-3072"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(KeyContext.Kind.NONE))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_RSA_KEYGEN_BITS_4096 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_CTX_set_rsa_keygen_bits")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RSA-4096"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(KeyContext.Kind.NONE))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // DSA Key Generation
    // ====================================================================

    private static final IDetectionRule<AstNode> EVP_PKEY_CTX_NEW_DSA =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_CTX_new_id")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DSA"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(KeyContext.Kind.NONE))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_DSA_PARAMGEN_BITS_2048 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_CTX_set_dsa_paramgen_bits")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DSA-2048"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(KeyContext.Kind.NONE))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_DSA_PARAMGEN_BITS_3072 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_CTX_set_dsa_paramgen_bits")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DSA-3072"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(KeyContext.Kind.NONE))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // EC Key Generation
    // ====================================================================

    private static final IDetectionRule<AstNode> EVP_PKEY_CTX_NEW_EC =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_CTX_new_id")
                    .shouldBeDetectedAs(new ValueActionFactory<>("EC"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(KeyContext.Kind.NONE))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_EC_CURVE_P256 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_CTX_set_ec_paramgen_curve_nid")
                    .shouldBeDetectedAs(new ValueActionFactory<>("EC-P256"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(KeyContext.Kind.NONE))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_EC_CURVE_P384 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_CTX_set_ec_paramgen_curve_nid")
                    .shouldBeDetectedAs(new ValueActionFactory<>("EC-P384"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(KeyContext.Kind.NONE))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_EC_CURVE_P521 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_CTX_set_ec_paramgen_curve_nid")
                    .shouldBeDetectedAs(new ValueActionFactory<>("EC-P521"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(KeyContext.Kind.NONE))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_EC_CURVE_SECP256K1 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_CTX_set_ec_paramgen_curve_nid")
                    .shouldBeDetectedAs(new ValueActionFactory<>("EC-SECP256K1"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(KeyContext.Kind.NONE))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_EC_CURVE_BP256R1 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_CTX_set_ec_paramgen_curve_nid")
                    .shouldBeDetectedAs(new ValueActionFactory<>("EC-BRAINPOOLP256R1"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(KeyContext.Kind.NONE))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_EC_CURVE_BP384R1 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_CTX_set_ec_paramgen_curve_nid")
                    .shouldBeDetectedAs(new ValueActionFactory<>("EC-BRAINPOOLP384R1"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(KeyContext.Kind.NONE))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_EC_CURVE_BP512R1 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_CTX_set_ec_paramgen_curve_nid")
                    .shouldBeDetectedAs(new ValueActionFactory<>("EC-BRAINPOOLP512R1"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(KeyContext.Kind.NONE))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // DH Key Generation
    // ====================================================================

    private static final IDetectionRule<AstNode> EVP_PKEY_CTX_NEW_DH =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_CTX_new_id")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DH"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(KeyContext.Kind.NONE))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_DH_PARAMGEN_2048 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_CTX_set_dh_paramgen_prime_len")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DH-2048"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(KeyContext.Kind.NONE))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_DH_PARAMGEN_4096 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_CTX_set_dh_paramgen_prime_len")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DH-4096"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(KeyContext.Kind.NONE))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // EdDSA Key Generation
    // ====================================================================

    private static final IDetectionRule<AstNode> EVP_PKEY_CTX_NEW_ED25519 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_CTX_new_id")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ED25519"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(KeyContext.Kind.NONE))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_PKEY_CTX_NEW_ED448 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_CTX_new_id")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ED448"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(KeyContext.Kind.NONE))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // X25519/X448 Key Generation
    // ====================================================================

    private static final IDetectionRule<AstNode> EVP_PKEY_CTX_NEW_X25519 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_CTX_new_id")
                    .shouldBeDetectedAs(new ValueActionFactory<>("X25519"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(KeyContext.Kind.NONE))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_PKEY_CTX_NEW_X448 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_CTX_new_id")
                    .shouldBeDetectedAs(new ValueActionFactory<>("X448"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(KeyContext.Kind.NONE))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // Post-Quantum Key Generation - ML-KEM (Kyber)
    // ====================================================================

    private static final IDetectionRule<AstNode> EVP_PKEY_CTX_NEW_MLKEM512 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_CTX_new_from_name")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ML-KEM-512"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(KeyContext.Kind.NONE))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_PKEY_CTX_NEW_MLKEM768 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_CTX_new_from_name")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ML-KEM-768"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(KeyContext.Kind.NONE))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_PKEY_CTX_NEW_MLKEM1024 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_CTX_new_from_name")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ML-KEM-1024"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(KeyContext.Kind.NONE))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // Hybrid Post-Quantum KEMs (PQC + Classical)
    // ====================================================================

    private static final IDetectionRule<AstNode> EVP_PKEY_CTX_NEW_X25519MLKEM768 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_CTX_new_from_name")
                    .shouldBeDetectedAs(new ValueActionFactory<>("X25519MLKEM768"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(KeyContext.Kind.NONE))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_PKEY_CTX_NEW_X448MLKEM1024 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_CTX_new_from_name")
                    .shouldBeDetectedAs(new ValueActionFactory<>("X448MLKEM1024"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(KeyContext.Kind.NONE))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_PKEY_CTX_NEW_SECP256R1MLKEM768 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_CTX_new_from_name")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SecP256r1MLKEM768"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(KeyContext.Kind.NONE))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_PKEY_CTX_NEW_SECP384R1MLKEM1024 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_CTX_new_from_name")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SecP384r1MLKEM1024"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(KeyContext.Kind.NONE))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // Post-Quantum Key Generation - ML-DSA
    // ====================================================================

    private static final IDetectionRule<AstNode> EVP_PKEY_CTX_NEW_MLDSA44 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_CTX_new_from_name")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ML-DSA-44"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(KeyContext.Kind.NONE))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_PKEY_CTX_NEW_MLDSA65 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_CTX_new_from_name")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ML-DSA-65"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(KeyContext.Kind.NONE))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_PKEY_CTX_NEW_MLDSA87 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_CTX_new_from_name")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ML-DSA-87"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(KeyContext.Kind.NONE))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // Post-Quantum Key Generation - SLH-DSA
    // ====================================================================

    private static final IDetectionRule<AstNode> EVP_PKEY_CTX_NEW_SLH_DSA_SHA2_128F =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_CTX_new_from_name")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SLH-DSA-SHA2-128F"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(KeyContext.Kind.NONE))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_PKEY_CTX_NEW_SLH_DSA_SHA2_128S =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_CTX_new_from_name")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SLH-DSA-SHA2-128S"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(KeyContext.Kind.NONE))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_PKEY_CTX_NEW_SLH_DSA_SHAKE_128F =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_CTX_new_from_name")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SLH-DSA-SHAKE-128F"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(KeyContext.Kind.NONE))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_PKEY_CTX_NEW_SLH_DSA_SHA2_192F =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_CTX_new_from_name")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SLH-DSA-SHA2-192F"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(KeyContext.Kind.NONE))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_PKEY_CTX_NEW_SLH_DSA_SHAKE_128S =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_CTX_new_from_name")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SLH-DSA-SHAKE-128S"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(KeyContext.Kind.NONE))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_PKEY_CTX_NEW_SLH_DSA_SHA2_192S =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_CTX_new_from_name")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SLH-DSA-SHA2-192S"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(KeyContext.Kind.NONE))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_PKEY_CTX_NEW_SLH_DSA_SHAKE_192F =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_CTX_new_from_name")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SLH-DSA-SHAKE-192F"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(KeyContext.Kind.NONE))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_PKEY_CTX_NEW_SLH_DSA_SHAKE_192S =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_CTX_new_from_name")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SLH-DSA-SHAKE-192S"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(KeyContext.Kind.NONE))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_PKEY_CTX_NEW_SLH_DSA_SHA2_256F =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_CTX_new_from_name")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SLH-DSA-SHA2-256F"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(KeyContext.Kind.NONE))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_PKEY_CTX_NEW_SLH_DSA_SHA2_256S =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_CTX_new_from_name")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SLH-DSA-SHA2-256S"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(KeyContext.Kind.NONE))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_PKEY_CTX_NEW_SLH_DSA_SHAKE_256F =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_CTX_new_from_name")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SLH-DSA-SHAKE-256F"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(KeyContext.Kind.NONE))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_PKEY_CTX_NEW_SLH_DSA_SHAKE_256S =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_CTX_new_from_name")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SLH-DSA-SHAKE-256S"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(KeyContext.Kind.NONE))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // EVP_PKEY_keygen (generic keygen detection)
    // ====================================================================

    private static final IDetectionRule<AstNode> EVP_PKEY_KEYGEN =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_keygen")
                    .shouldBeDetectedAs(new ValueActionFactory<>("KEYGEN"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(KeyContext.Kind.NONE))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_PKEY_KEYGEN_INIT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_keygen_init")
                    .shouldBeDetectedAs(new ValueActionFactory<>("KEYGEN-INIT"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(KeyContext.Kind.NONE))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // SM2
    // ====================================================================

    private static final IDetectionRule<AstNode> EVP_PKEY_CTX_NEW_SM2 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_CTX_new_from_name")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SM2"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext(KeyContext.Kind.NONE))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private OpenSSLEvpKeyGen() {
        // nothing
    }

    @Nonnull
    public static List<IDetectionRule<AstNode>> rules() {
        return List.of(
                // RSA
                EVP_PKEY_CTX_NEW_RSA,
                EVP_PKEY_CTX_NEW_RSA_PSS,
                EVP_RSA_KEYGEN_BITS_2048,
                EVP_RSA_KEYGEN_BITS_3072,
                EVP_RSA_KEYGEN_BITS_4096,
                // DSA
                EVP_PKEY_CTX_NEW_DSA,
                EVP_DSA_PARAMGEN_BITS_2048,
                EVP_DSA_PARAMGEN_BITS_3072,
                // EC
                EVP_PKEY_CTX_NEW_EC,
                EVP_EC_CURVE_P256,
                EVP_EC_CURVE_P384,
                EVP_EC_CURVE_P521,
                EVP_EC_CURVE_SECP256K1,
                EVP_EC_CURVE_BP256R1,
                EVP_EC_CURVE_BP384R1,
                EVP_EC_CURVE_BP512R1,
                // DH
                EVP_PKEY_CTX_NEW_DH,
                EVP_DH_PARAMGEN_2048,
                EVP_DH_PARAMGEN_4096,
                // EdDSA
                EVP_PKEY_CTX_NEW_ED25519,
                EVP_PKEY_CTX_NEW_ED448,
                // X25519/X448
                EVP_PKEY_CTX_NEW_X25519,
                EVP_PKEY_CTX_NEW_X448,
                // ML-KEM
                EVP_PKEY_CTX_NEW_MLKEM512,
                EVP_PKEY_CTX_NEW_MLKEM768,
                EVP_PKEY_CTX_NEW_MLKEM1024,
                // Hybrid PQC KEMs
                EVP_PKEY_CTX_NEW_X25519MLKEM768,
                EVP_PKEY_CTX_NEW_X448MLKEM1024,
                EVP_PKEY_CTX_NEW_SECP256R1MLKEM768,
                EVP_PKEY_CTX_NEW_SECP384R1MLKEM1024,
                // ML-DSA
                EVP_PKEY_CTX_NEW_MLDSA44,
                EVP_PKEY_CTX_NEW_MLDSA65,
                EVP_PKEY_CTX_NEW_MLDSA87,
                // SLH-DSA
                EVP_PKEY_CTX_NEW_SLH_DSA_SHA2_128F,
                EVP_PKEY_CTX_NEW_SLH_DSA_SHA2_128S,
                EVP_PKEY_CTX_NEW_SLH_DSA_SHAKE_128F,
                EVP_PKEY_CTX_NEW_SLH_DSA_SHAKE_128S,
                EVP_PKEY_CTX_NEW_SLH_DSA_SHA2_192F,
                EVP_PKEY_CTX_NEW_SLH_DSA_SHA2_192S,
                EVP_PKEY_CTX_NEW_SLH_DSA_SHAKE_192F,
                EVP_PKEY_CTX_NEW_SLH_DSA_SHAKE_192S,
                EVP_PKEY_CTX_NEW_SLH_DSA_SHA2_256F,
                EVP_PKEY_CTX_NEW_SLH_DSA_SHA2_256S,
                EVP_PKEY_CTX_NEW_SLH_DSA_SHAKE_256F,
                EVP_PKEY_CTX_NEW_SLH_DSA_SHAKE_256S,
                // Generic keygen
                // SM2
                EVP_PKEY_CTX_NEW_SM2,
                // Generic keygen
                EVP_PKEY_KEYGEN,
                EVP_PKEY_KEYGEN_INIT);
    }
}
