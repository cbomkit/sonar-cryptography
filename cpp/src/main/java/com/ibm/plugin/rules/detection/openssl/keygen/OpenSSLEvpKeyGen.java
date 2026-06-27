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

    private static final IDetectionRule<AstNode> EVP_RSA_KEYGEN_BITS_2048 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_CTX_set_rsa_keygen_bits")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RSA-2048"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_RSA_KEYGEN_BITS_3072 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_CTX_set_rsa_keygen_bits")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RSA-3072"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_RSA_KEYGEN_BITS_4096 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_CTX_set_rsa_keygen_bits")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RSA-4096"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // DSA Key Generation
    // ====================================================================

    private static final IDetectionRule<AstNode> EVP_DSA_PARAMGEN_BITS_2048 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_CTX_set_dsa_paramgen_bits")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DSA-2048"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_DSA_PARAMGEN_BITS_3072 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_CTX_set_dsa_paramgen_bits")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DSA-3072"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // EC Key Generation
    // ====================================================================

    private static final IDetectionRule<AstNode> EVP_EC_CURVE_P256 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_CTX_set_ec_paramgen_curve_nid")
                    .shouldBeDetectedAs(new ValueActionFactory<>("EC-P256"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_EC_CURVE_P384 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_CTX_set_ec_paramgen_curve_nid")
                    .shouldBeDetectedAs(new ValueActionFactory<>("EC-P384"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_EC_CURVE_P521 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_CTX_set_ec_paramgen_curve_nid")
                    .shouldBeDetectedAs(new ValueActionFactory<>("EC-P521"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_EC_CURVE_SECP256K1 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_CTX_set_ec_paramgen_curve_nid")
                    .shouldBeDetectedAs(new ValueActionFactory<>("EC-SECP256K1"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_EC_CURVE_BP256R1 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_CTX_set_ec_paramgen_curve_nid")
                    .shouldBeDetectedAs(new ValueActionFactory<>("EC-BRAINPOOLP256R1"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_EC_CURVE_BP384R1 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_CTX_set_ec_paramgen_curve_nid")
                    .shouldBeDetectedAs(new ValueActionFactory<>("EC-BRAINPOOLP384R1"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_EC_CURVE_BP512R1 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_CTX_set_ec_paramgen_curve_nid")
                    .shouldBeDetectedAs(new ValueActionFactory<>("EC-BRAINPOOLP512R1"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext())
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
                    .buildForContext(new KeyContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_PKEY_KEYGEN_INIT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_keygen_init")
                    .shouldBeDetectedAs(new ValueActionFactory<>("KEYGEN-INIT"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // Generate / paramgen
    // ====================================================================

    private static final IDetectionRule<AstNode> EVP_PKEY_GENERATE =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_generate")
                    .shouldBeDetectedAs(new ValueActionFactory<>("KEYGEN"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_PKEY_Q_KEYGEN =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_Q_keygen")
                    .shouldBeDetectedAs(new ValueActionFactory<>("KEYGEN"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_PKEY_PARAMGEN =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_paramgen")
                    .shouldBeDetectedAs(new ValueActionFactory<>("PARAMGEN"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_PKEY_PARAMGEN_INIT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_paramgen_init")
                    .shouldBeDetectedAs(new ValueActionFactory<>("PARAMGEN"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // KEYMGMT fetch
    // ====================================================================

    private static final IDetectionRule<AstNode> EVP_KEYMGMT_FETCH =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_KEYMGMT_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("KEYMGMT-FETCH"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // Group / curve selection setters
    // ====================================================================

    private static final IDetectionRule<AstNode> EVP_PKEY_CTX_SET_GROUP_NAME =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_CTX_set_group_name")
                    .shouldBeDetectedAs(new ValueActionFactory<>("GROUP-NAME"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_PKEY_CTX_SET_EC_PARAM_ENC =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_CTX_set_ec_param_enc")
                    .shouldBeDetectedAs(new ValueActionFactory<>("EC-PARAM-ENC"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // RSA keygen pubexp/primes
    // ====================================================================

    private static final IDetectionRule<AstNode> EVP_PKEY_CTX_SET1_RSA_KEYGEN_PUBEXP =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_CTX_set1_rsa_keygen_pubexp")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RSA-KEYGEN-PUBEXP"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_PKEY_CTX_SET_RSA_KEYGEN_PRIMES =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_CTX_set_rsa_keygen_primes")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RSA-KEYGEN-PRIMES"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // DSA paramgen extras
    // ====================================================================

    private static final IDetectionRule<AstNode> EVP_PKEY_CTX_SET_DSA_PARAMGEN_Q_BITS =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_CTX_set_dsa_paramgen_q_bits")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DSA-PARAMGEN-Q-BITS"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_PKEY_CTX_SET_DSA_PARAMGEN_MD =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_CTX_set_dsa_paramgen_md")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DSA-PARAMGEN-MD"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_PKEY_CTX_SET_DSA_PARAMGEN_MD_PROPS =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_CTX_set_dsa_paramgen_md_props")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DSA-PARAMGEN-MD"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_PKEY_CTX_SET_DSA_PARAMGEN_TYPE =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_CTX_set_dsa_paramgen_type")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DSA-PARAMGEN-TYPE"))
                    .withAnyParameters()
                    .buildForContext(new KeyContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private OpenSSLEvpKeyGen() {
        // nothing
    }

    @Nonnull
    public static List<IDetectionRule<AstNode>> rules() {
        return List.of(
                // RSA
                EVP_RSA_KEYGEN_BITS_2048,
                EVP_RSA_KEYGEN_BITS_3072,
                EVP_RSA_KEYGEN_BITS_4096,
                // DSA
                EVP_DSA_PARAMGEN_BITS_2048,
                EVP_DSA_PARAMGEN_BITS_3072,
                // EC
                EVP_EC_CURVE_P256,
                EVP_EC_CURVE_P384,
                EVP_EC_CURVE_P521,
                EVP_EC_CURVE_SECP256K1,
                EVP_EC_CURVE_BP256R1,
                EVP_EC_CURVE_BP384R1,
                EVP_EC_CURVE_BP512R1,
                // Generic keygen
                EVP_PKEY_KEYGEN,
                EVP_PKEY_KEYGEN_INIT,
                // Generate / paramgen
                EVP_PKEY_GENERATE,
                EVP_PKEY_Q_KEYGEN,
                EVP_PKEY_PARAMGEN,
                EVP_PKEY_PARAMGEN_INIT,
                // KEYMGMT fetch
                EVP_KEYMGMT_FETCH,
                // Group/curve selection
                EVP_PKEY_CTX_SET_GROUP_NAME,
                EVP_PKEY_CTX_SET_EC_PARAM_ENC,
                // RSA keygen pubexp/primes
                EVP_PKEY_CTX_SET1_RSA_KEYGEN_PUBEXP,
                EVP_PKEY_CTX_SET_RSA_KEYGEN_PRIMES,
                // DSA paramgen extras
                EVP_PKEY_CTX_SET_DSA_PARAMGEN_Q_BITS,
                EVP_PKEY_CTX_SET_DSA_PARAMGEN_MD,
                EVP_PKEY_CTX_SET_DSA_PARAMGEN_MD_PROPS,
                EVP_PKEY_CTX_SET_DSA_PARAMGEN_TYPE);
    }
}
