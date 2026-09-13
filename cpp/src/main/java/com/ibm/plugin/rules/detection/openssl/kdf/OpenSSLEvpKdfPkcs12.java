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
package com.ibm.plugin.rules.detection.openssl.kdf;

import com.ibm.engine.model.context.KeyDerivationFunctionContext;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.plugin.rules.detection.Memoize;
import com.ibm.plugin.rules.detection.openssl.digest.OpenSSLEvpMessageDigest;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.List;
import java.util.function.Supplier;
import javax.annotation.Nonnull;

/**
 * Detection rules for OpenSSL PKCS#12 and PKCS#5 password-based key derivation: the EVP_KDF
 * PKCS12KDF fetch, the legacy PKCS5_PBKDF2_HMAC(_SHA1) functions, the PKCS12_create/set_mac/
 * key_gen family, and the legacy PKCS5 PBE keyivgen functions.
 */
@SuppressWarnings("java:S1192")
public final class OpenSSLEvpKdfPkcs12 {

    private static final String BUNDLE = "OpenSSL";

    private static final IDetectionRule<AstNode> PKCS12KDF =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_KDF_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("PKCS12KDF"))
                    .withMethodParameter("*")
                    .withMethodParameter("\"PKCS12KDF\"")
                    .withMethodParameter("*")
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> PKCS5_PBKDF2_HMAC =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("PKCS5_PBKDF2_HMAC")
                    .shouldBeDetectedAs(new ValueActionFactory<>("PBKDF2-HMAC"))
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .addDependingDetectionRules(OpenSSLEvpMessageDigest.rules())
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> PKCS5_PBKDF2_HMAC_SHA1 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("PKCS5_PBKDF2_HMAC_SHA1")
                    .shouldBeDetectedAs(new ValueActionFactory<>("PBKDF2-HMAC-SHA1"))
                    .withAnyParameters()
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> PKCS12_CREATE =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("PKCS12_create")
                    .shouldBeDetectedAs(new ValueActionFactory<>("PKCS12"))
                    .withAnyParameters()
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> PKCS12_CREATE_EX =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("PKCS12_create_ex")
                    .shouldBeDetectedAs(new ValueActionFactory<>("PKCS12"))
                    .withAnyParameters()
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> PKCS12_CREATE_EX2 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("PKCS12_create_ex2")
                    .shouldBeDetectedAs(new ValueActionFactory<>("PKCS12"))
                    .withAnyParameters()
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> PKCS12_SET_MAC =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("PKCS12_set_mac")
                    .shouldBeDetectedAs(new ValueActionFactory<>("PKCS12-MAC"))
                    .withAnyParameters()
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> PKCS12_PBE_KEYIVGEN =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("PKCS12_PBE_keyivgen")
                    .shouldBeDetectedAs(new ValueActionFactory<>("PKCS12-PBE"))
                    .withAnyParameters()
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> PKCS12_PBE_KEYIVGEN_EX =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("PKCS12_PBE_keyivgen_ex")
                    .shouldBeDetectedAs(new ValueActionFactory<>("PKCS12-PBE"))
                    .withAnyParameters()
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> PKCS12_KEY_GEN_ASC =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("PKCS12_key_gen_asc")
                    .shouldBeDetectedAs(new ValueActionFactory<>("PKCS12-KDF"))
                    .withAnyParameters()
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> PKCS12_KEY_GEN_ASC_EX =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("PKCS12_key_gen_asc_ex")
                    .shouldBeDetectedAs(new ValueActionFactory<>("PKCS12-KDF"))
                    .withAnyParameters()
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> PKCS12_KEY_GEN_UNI =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("PKCS12_key_gen_uni")
                    .shouldBeDetectedAs(new ValueActionFactory<>("PKCS12-KDF"))
                    .withAnyParameters()
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> PKCS12_KEY_GEN_UNI_EX =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("PKCS12_key_gen_uni_ex")
                    .shouldBeDetectedAs(new ValueActionFactory<>("PKCS12-KDF"))
                    .withAnyParameters()
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> PKCS12_KEY_GEN_UTF8 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("PKCS12_key_gen_utf8")
                    .shouldBeDetectedAs(new ValueActionFactory<>("PKCS12-KDF"))
                    .withAnyParameters()
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> PKCS12_KEY_GEN_UTF8_EX =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("PKCS12_key_gen_utf8_ex")
                    .shouldBeDetectedAs(new ValueActionFactory<>("PKCS12-KDF"))
                    .withAnyParameters()
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> PKCS5_PBE_KEYIVGEN =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("PKCS5_PBE_keyivgen")
                    .shouldBeDetectedAs(new ValueActionFactory<>("PBE-KEYIVGEN"))
                    .withAnyParameters()
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> PKCS5_PBE_KEYIVGEN_EX =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("PKCS5_PBE_keyivgen_ex")
                    .shouldBeDetectedAs(new ValueActionFactory<>("PBE-KEYIVGEN"))
                    .withAnyParameters()
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private OpenSSLEvpKdfPkcs12() {
        // private
    }

    @Nonnull
    private static List<IDetectionRule<AstNode>> buildRules() {
        return List.of(
                // PKCS12KDF - PKCS#12 Key Derivation Function
                PKCS12KDF,
                // Legacy PBKDF2 functions
                PKCS5_PBKDF2_HMAC,
                PKCS5_PBKDF2_HMAC_SHA1,
                // PKCS#12 KDF / MAC entry points
                PKCS12_CREATE,
                PKCS12_CREATE_EX,
                PKCS12_CREATE_EX2,
                PKCS12_SET_MAC,
                PKCS12_PBE_KEYIVGEN,
                PKCS12_PBE_KEYIVGEN_EX,
                PKCS12_KEY_GEN_ASC,
                PKCS12_KEY_GEN_ASC_EX,
                PKCS12_KEY_GEN_UNI,
                PKCS12_KEY_GEN_UNI_EX,
                PKCS12_KEY_GEN_UTF8,
                PKCS12_KEY_GEN_UTF8_EX,
                // PKCS5 PBE keyivgen (legacy)
                PKCS5_PBE_KEYIVGEN,
                PKCS5_PBE_KEYIVGEN_EX);
    }

    private static final Supplier<List<IDetectionRule<AstNode>>> RULES =
            Memoize.of(OpenSSLEvpKdfPkcs12::buildRules);

    @Nonnull
    public static List<IDetectionRule<AstNode>> rules() {
        return RULES.get();
    }
}
