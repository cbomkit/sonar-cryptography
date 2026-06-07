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

import com.ibm.engine.model.context.CipherContext;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.List;
import javax.annotation.Nonnull;

/**
 * Detection rules for OpenSSL legacy cipher APIs.
 *
 * <p>These rules detect direct cipher operations using the legacy (pre-EVP) APIs. These APIs are
 * deprecated but still widely used in existing codebases.
 *
 * <p>Covers: AES, DES, 3DES, Blowfish, RC4, RC2, CAST, IDEA
 */
@SuppressWarnings("java:S1192")
public final class OpenSSLLegacyCipher {

    private static final String BUNDLE = "OpenSSL";

    // ====================================================================
    // Legacy AES functions
    // ====================================================================

    private static final IDetectionRule<AstNode> AES_SET_ENCRYPT_KEY =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("AES_set_encrypt_key")
                    .shouldBeDetectedAs(new ValueActionFactory<>("AES"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> AES_SET_DECRYPT_KEY =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("AES_set_decrypt_key")
                    .shouldBeDetectedAs(new ValueActionFactory<>("AES"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> AES_ECB_ENCRYPT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("AES_ecb_encrypt")
                    .shouldBeDetectedAs(new ValueActionFactory<>("AES-ECB"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> AES_CBC_ENCRYPT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("AES_cbc_encrypt")
                    .shouldBeDetectedAs(new ValueActionFactory<>("AES-CBC"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> AES_CFB128_ENCRYPT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("AES_cfb128_encrypt")
                    .shouldBeDetectedAs(new ValueActionFactory<>("AES-CFB128"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> AES_OFB128_ENCRYPT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("AES_ofb128_encrypt")
                    .shouldBeDetectedAs(new ValueActionFactory<>("AES-OFB"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> AES_IGE_ENCRYPT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("AES_ige_encrypt")
                    .shouldBeDetectedAs(new ValueActionFactory<>("AES-IGE"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> AES_CFB1_ENCRYPT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("AES_cfb1_encrypt")
                    .shouldBeDetectedAs(new ValueActionFactory<>("AES-CFB1"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> AES_CFB8_ENCRYPT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("AES_cfb8_encrypt")
                    .shouldBeDetectedAs(new ValueActionFactory<>("AES-CFB8"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> AES_BI_IGE_ENCRYPT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("AES_bi_ige_encrypt")
                    .shouldBeDetectedAs(new ValueActionFactory<>("AES-BI-IGE"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // Legacy DES functions
    // ====================================================================

    private static final IDetectionRule<AstNode> DES_SET_KEY =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("DES_set_key", "DES_set_key_checked", "DES_set_key_unchecked")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DES"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> DES_ECB_ENCRYPT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("DES_ecb_encrypt")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DES-ECB"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> DES_CBC_ENCRYPT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("DES_ncbc_encrypt", "DES_cbc_encrypt")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DES-CBC"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> DES_CFB_ENCRYPT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("DES_cfb64_encrypt", "DES_cfb_encrypt")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DES-CFB"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> DES_OFB_ENCRYPT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("DES_ofb64_encrypt")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DES-OFB"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> DES_EDE3_CBC_ENCRYPT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("DES_ede3_cbc_encrypt")
                    .shouldBeDetectedAs(new ValueActionFactory<>("3DES-CBC"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> DES_EDE3_ECB_ENCRYPT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("DES_ecb3_encrypt")
                    .shouldBeDetectedAs(new ValueActionFactory<>("3DES-ECB"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> DES_EDE3_CFB_ENCRYPT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("DES_ede3_cfb64_encrypt", "DES_ede3_cfb_encrypt")
                    .shouldBeDetectedAs(new ValueActionFactory<>("3DES-CFB"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> DES_EDE3_OFB64_ENCRYPT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("DES_ede3_ofb64_encrypt")
                    .shouldBeDetectedAs(new ValueActionFactory<>("3DES-OFB"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> DES_XCBC_ENCRYPT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("DES_xcbc_encrypt")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DES-XCBC"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // Legacy Blowfish functions
    // ====================================================================

    private static final IDetectionRule<AstNode> BF_SET_KEY =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("BF_set_key")
                    .shouldBeDetectedAs(new ValueActionFactory<>("BLOWFISH"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> BF_ECB_ENCRYPT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("BF_ecb_encrypt")
                    .shouldBeDetectedAs(new ValueActionFactory<>("BLOWFISH-ECB"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> BF_CBC_ENCRYPT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("BF_cbc_encrypt")
                    .shouldBeDetectedAs(new ValueActionFactory<>("BLOWFISH-CBC"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> BF_CFB64_ENCRYPT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("BF_cfb64_encrypt")
                    .shouldBeDetectedAs(new ValueActionFactory<>("BLOWFISH-CFB"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> BF_OFB64_ENCRYPT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("BF_ofb64_encrypt")
                    .shouldBeDetectedAs(new ValueActionFactory<>("BLOWFISH-OFB"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // Legacy RC4 functions
    // ====================================================================

    private static final IDetectionRule<AstNode> RC4_SET_KEY =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("RC4_set_key")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RC4"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> RC4 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("RC4")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RC4"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // Legacy RC2 functions
    // ====================================================================

    private static final IDetectionRule<AstNode> RC2_SET_KEY =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("RC2_set_key")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RC2"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> RC2_ECB_ENCRYPT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("RC2_ecb_encrypt")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RC2-ECB"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> RC2_CBC_ENCRYPT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("RC2_cbc_encrypt")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RC2-CBC"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> RC2_CFB64_ENCRYPT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("RC2_cfb64_encrypt")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RC2-CFB"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> RC2_OFB64_ENCRYPT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("RC2_ofb64_encrypt")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RC2-OFB"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // Legacy CAST functions
    // ====================================================================

    private static final IDetectionRule<AstNode> CAST_SET_KEY =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("CAST_set_key")
                    .shouldBeDetectedAs(new ValueActionFactory<>("CAST5"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> CAST_ECB_ENCRYPT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("CAST_ecb_encrypt")
                    .shouldBeDetectedAs(new ValueActionFactory<>("CAST5-ECB"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> CAST_CBC_ENCRYPT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("CAST_cbc_encrypt")
                    .shouldBeDetectedAs(new ValueActionFactory<>("CAST5-CBC"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> CAST_CFB64_ENCRYPT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("CAST_cfb64_encrypt")
                    .shouldBeDetectedAs(new ValueActionFactory<>("CAST5-CFB"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> CAST_OFB64_ENCRYPT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("CAST_ofb64_encrypt")
                    .shouldBeDetectedAs(new ValueActionFactory<>("CAST5-OFB"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // Legacy IDEA functions
    // ====================================================================

    private static final IDetectionRule<AstNode> IDEA_SET_ENCRYPT_KEY =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("IDEA_set_encrypt_key")
                    .shouldBeDetectedAs(new ValueActionFactory<>("IDEA"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> IDEA_SET_DECRYPT_KEY =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("IDEA_set_decrypt_key")
                    .shouldBeDetectedAs(new ValueActionFactory<>("IDEA"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> IDEA_ECB_ENCRYPT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("IDEA_ecb_encrypt")
                    .shouldBeDetectedAs(new ValueActionFactory<>("IDEA-ECB"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> IDEA_CBC_ENCRYPT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("IDEA_cbc_encrypt")
                    .shouldBeDetectedAs(new ValueActionFactory<>("IDEA-CBC"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> IDEA_CFB64_ENCRYPT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("IDEA_cfb64_encrypt")
                    .shouldBeDetectedAs(new ValueActionFactory<>("IDEA-CFB"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> IDEA_OFB64_ENCRYPT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("IDEA_ofb64_encrypt")
                    .shouldBeDetectedAs(new ValueActionFactory<>("IDEA-OFB"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // Legacy Camellia functions
    // ====================================================================

    private static final IDetectionRule<AstNode> CAMELLIA_SET_KEY =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("Camellia_set_key")
                    .shouldBeDetectedAs(new ValueActionFactory<>("CAMELLIA"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> CAMELLIA_ECB_ENCRYPT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("Camellia_ecb_encrypt")
                    .shouldBeDetectedAs(new ValueActionFactory<>("CAMELLIA-ECB"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> CAMELLIA_CBC_ENCRYPT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("Camellia_cbc_encrypt")
                    .shouldBeDetectedAs(new ValueActionFactory<>("CAMELLIA-CBC"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> CAMELLIA_CFB128_ENCRYPT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("Camellia_cfb128_encrypt")
                    .shouldBeDetectedAs(new ValueActionFactory<>("CAMELLIA-CFB128"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> CAMELLIA_CFB1_ENCRYPT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("Camellia_cfb1_encrypt")
                    .shouldBeDetectedAs(new ValueActionFactory<>("CAMELLIA-CFB1"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> CAMELLIA_CFB8_ENCRYPT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("Camellia_cfb8_encrypt")
                    .shouldBeDetectedAs(new ValueActionFactory<>("CAMELLIA-CFB8"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> CAMELLIA_OFB128_ENCRYPT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("Camellia_ofb128_encrypt")
                    .shouldBeDetectedAs(new ValueActionFactory<>("CAMELLIA-OFB"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> CAMELLIA_CTR128_ENCRYPT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("Camellia_ctr128_encrypt")
                    .shouldBeDetectedAs(new ValueActionFactory<>("CAMELLIA-CTR"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // Legacy RC5 functions
    // ====================================================================

    private static final IDetectionRule<AstNode> RC5_32_SET_KEY =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("RC5_32_set_key")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RC5"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> RC5_32_ECB_ENCRYPT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("RC5_32_ecb_encrypt")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RC5-ECB"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> RC5_32_CBC_ENCRYPT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("RC5_32_cbc_encrypt")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RC5-CBC"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> RC5_32_CFB64_ENCRYPT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("RC5_32_cfb64_encrypt")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RC5-CFB"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> RC5_32_OFB64_ENCRYPT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("RC5_32_ofb64_encrypt")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RC5-OFB"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // Legacy SEED functions
    // ====================================================================

    private static final IDetectionRule<AstNode> SEED_SET_KEY =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("SEED_set_key")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SEED"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> SEED_ECB_ENCRYPT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("SEED_ecb_encrypt")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SEED-ECB"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> SEED_CBC_ENCRYPT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("SEED_cbc_encrypt")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SEED-CBC"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> SEED_CFB128_ENCRYPT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("SEED_cfb128_encrypt")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SEED-CFB"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> SEED_OFB128_ENCRYPT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("SEED_ofb128_encrypt")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SEED-OFB"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private OpenSSLLegacyCipher() {
        // nothing
    }

    @Nonnull
    public static List<IDetectionRule<AstNode>> rules() {
        return List.of(
                // AES
                AES_SET_ENCRYPT_KEY,
                AES_SET_DECRYPT_KEY,
                AES_ECB_ENCRYPT,
                AES_CBC_ENCRYPT,
                AES_CFB128_ENCRYPT,
                AES_OFB128_ENCRYPT,
                AES_IGE_ENCRYPT,
                AES_CFB1_ENCRYPT,
                AES_CFB8_ENCRYPT,
                AES_BI_IGE_ENCRYPT,
                // DES
                DES_SET_KEY,
                DES_ECB_ENCRYPT,
                DES_CBC_ENCRYPT,
                DES_CFB_ENCRYPT,
                DES_OFB_ENCRYPT,
                DES_EDE3_CBC_ENCRYPT,
                DES_EDE3_ECB_ENCRYPT,
                DES_EDE3_CFB_ENCRYPT,
                DES_EDE3_OFB64_ENCRYPT,
                DES_XCBC_ENCRYPT,
                // Blowfish
                BF_SET_KEY,
                BF_ECB_ENCRYPT,
                BF_CBC_ENCRYPT,
                BF_CFB64_ENCRYPT,
                BF_OFB64_ENCRYPT,
                // RC4
                RC4_SET_KEY,
                RC4,
                // RC2
                RC2_SET_KEY,
                RC2_ECB_ENCRYPT,
                RC2_CBC_ENCRYPT,
                RC2_CFB64_ENCRYPT,
                RC2_OFB64_ENCRYPT,
                // CAST
                CAST_SET_KEY,
                CAST_ECB_ENCRYPT,
                CAST_CBC_ENCRYPT,
                CAST_CFB64_ENCRYPT,
                CAST_OFB64_ENCRYPT,
                // IDEA
                IDEA_SET_ENCRYPT_KEY,
                IDEA_SET_DECRYPT_KEY,
                IDEA_ECB_ENCRYPT,
                IDEA_CBC_ENCRYPT,
                IDEA_CFB64_ENCRYPT,
                IDEA_OFB64_ENCRYPT,
                // Camellia
                CAMELLIA_SET_KEY,
                CAMELLIA_ECB_ENCRYPT,
                CAMELLIA_CBC_ENCRYPT,
                CAMELLIA_CFB128_ENCRYPT,
                CAMELLIA_CFB1_ENCRYPT,
                CAMELLIA_CFB8_ENCRYPT,
                CAMELLIA_OFB128_ENCRYPT,
                CAMELLIA_CTR128_ENCRYPT,
                // RC5
                RC5_32_SET_KEY,
                RC5_32_ECB_ENCRYPT,
                RC5_32_CBC_ENCRYPT,
                RC5_32_CFB64_ENCRYPT,
                RC5_32_OFB64_ENCRYPT,
                // SEED
                SEED_SET_KEY,
                SEED_ECB_ENCRYPT,
                SEED_CBC_ENCRYPT,
                SEED_CFB128_ENCRYPT,
                SEED_OFB128_ENCRYPT);
    }
}
