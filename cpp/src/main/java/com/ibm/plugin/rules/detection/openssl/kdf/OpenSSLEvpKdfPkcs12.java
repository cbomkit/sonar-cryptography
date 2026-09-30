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
import com.ibm.engine.model.context.MacContext;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.plugin.rules.detection.Memoize;
import com.ibm.plugin.rules.detection.openssl.cipher.OpenSSLEvpCipher;
import com.ibm.plugin.rules.detection.openssl.digest.OpenSSLEvpMessageDigest;
import com.ibm.plugin.rules.detection.openssl.legacy.OpenSSLNidLookupFactory;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.List;
import java.util.function.Supplier;
import javax.annotation.Nonnull;

/**
 * Detection rules for the OpenSSL PKCS#12 and PKCS#5 password-based functions: the PKCS#12 key
 * derivation function (PKCS12_key_gen_*), the PKCS#12 and PKCS#5 v1.5 password-based encryption
 * schemes with the cipher and digest passed to PKCS12_PBE_keyivgen and PKCS5_PBE_keyivgen, the HMAC
 * set on a PKCS#12 container by PKCS12_set_mac, and the schemes that encrypt the key and the
 * certificates of a container created by PKCS12_create.
 */
@SuppressWarnings("java:S1192")
public final class OpenSSLEvpKdfPkcs12 {

    private static final String BUNDLE = "OpenSSL";

    // PKCS12_create(pass, name, pkey, cert, ca, nid_key, nid_cert, iter, mac_iter, keytype, ...):
    // nid_key and nid_cert select how the private key and the certificates are encrypted

    private static final OpenSSLNidLookupFactory PKCS12_ENCRYPTION =
            new OpenSSLNidLookupFactory(
                    OpenSSLNidLookupFactory.PKCS12_ENCRYPTION_BY_CODE,
                    OpenSSLNidLookupFactory.PKCS12_ENCRYPTION_BY_NAME);

    private static final IDetectionRule<AstNode> PKCS12_CREATE =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("PKCS12_create")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(PKCS12_ENCRYPTION)
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(PKCS12_ENCRYPTION)
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> PKCS12_CREATE_EX =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("PKCS12_create_ex")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(PKCS12_ENCRYPTION)
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(PKCS12_ENCRYPTION)
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> PKCS12_CREATE_EX2 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("PKCS12_create_ex2")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(PKCS12_ENCRYPTION)
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(PKCS12_ENCRYPTION)
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // PKCS12_set_mac(p12, pass, passlen, salt, saltlen, iter, md_type): the PKCS#12 MAC is an
    // HMAC with md_type

    private static final IDetectionRule<AstNode> PKCS12_SET_MAC =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("PKCS12_set_mac")
                    .shouldBeDetectedAs(new ValueActionFactory<>("HMAC"))
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .addDependingDetectionRules(OpenSSLEvpMessageDigest.rules())
                    .buildForContext(new MacContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // PKCS12_PBE_keyivgen(ctx, pass, passlen, param, cipher, md_type, en_de, ...) and
    // PKCS5_PBE_keyivgen(ctx, pass, passlen, param, cipher, md, en_de, ...)

    private static final IDetectionRule<AstNode> PKCS12_PBE_KEYIVGEN =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("PKCS12_PBE_keyivgen")
                    .shouldBeDetectedAs(new ValueActionFactory<>("PKCS12-PBE"))
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .addDependingDetectionRules(OpenSSLEvpCipher.cipherSelectionRules())
                    .withMethodParameter("*")
                    .addDependingDetectionRules(OpenSSLEvpMessageDigest.rules())
                    .withMethodParameter("*")
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> PKCS12_PBE_KEYIVGEN_EX =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("PKCS12_PBE_keyivgen_ex")
                    .shouldBeDetectedAs(new ValueActionFactory<>("PKCS12-PBE"))
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .addDependingDetectionRules(OpenSSLEvpCipher.cipherSelectionRules())
                    .withMethodParameter("*")
                    .addDependingDetectionRules(OpenSSLEvpMessageDigest.rules())
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> PKCS5_PBE_KEYIVGEN =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("PKCS5_PBE_keyivgen")
                    .shouldBeDetectedAs(new ValueActionFactory<>("PBES1"))
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .addDependingDetectionRules(OpenSSLEvpCipher.cipherSelectionRules())
                    .withMethodParameter("*")
                    .addDependingDetectionRules(OpenSSLEvpMessageDigest.rules())
                    .withMethodParameter("*")
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> PKCS5_PBE_KEYIVGEN_EX =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("PKCS5_PBE_keyivgen_ex")
                    .shouldBeDetectedAs(new ValueActionFactory<>("PBES1"))
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .addDependingDetectionRules(OpenSSLEvpCipher.cipherSelectionRules())
                    .withMethodParameter("*")
                    .addDependingDetectionRules(OpenSSLEvpMessageDigest.rules())
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // PKCS12_key_gen_*(pass, passlen, salt, saltlen, id, iter, n, out, md_type, ...)

    private static final IDetectionRule<AstNode> PKCS12_KEY_GEN_ASC =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("PKCS12_key_gen_asc")
                    .shouldBeDetectedAs(new ValueActionFactory<>("PKCS12KDF"))
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .addDependingDetectionRules(OpenSSLEvpMessageDigest.rules())
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> PKCS12_KEY_GEN_ASC_EX =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("PKCS12_key_gen_asc_ex")
                    .shouldBeDetectedAs(new ValueActionFactory<>("PKCS12KDF"))
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
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

    private static final IDetectionRule<AstNode> PKCS12_KEY_GEN_UNI =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("PKCS12_key_gen_uni")
                    .shouldBeDetectedAs(new ValueActionFactory<>("PKCS12KDF"))
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .addDependingDetectionRules(OpenSSLEvpMessageDigest.rules())
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> PKCS12_KEY_GEN_UNI_EX =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("PKCS12_key_gen_uni_ex")
                    .shouldBeDetectedAs(new ValueActionFactory<>("PKCS12KDF"))
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
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

    private static final IDetectionRule<AstNode> PKCS12_KEY_GEN_UTF8 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("PKCS12_key_gen_utf8")
                    .shouldBeDetectedAs(new ValueActionFactory<>("PKCS12KDF"))
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .addDependingDetectionRules(OpenSSLEvpMessageDigest.rules())
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> PKCS12_KEY_GEN_UTF8_EX =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("PKCS12_key_gen_utf8_ex")
                    .shouldBeDetectedAs(new ValueActionFactory<>("PKCS12KDF"))
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
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

    private OpenSSLEvpKdfPkcs12() {
        // private
    }

    @Nonnull
    private static List<IDetectionRule<AstNode>> buildRules() {
        return List.of(
                // PKCS#12 containers
                PKCS12_CREATE,
                PKCS12_CREATE_EX,
                PKCS12_CREATE_EX2,
                PKCS12_SET_MAC,
                // PKCS#12 and PKCS#5 password-based encryption
                PKCS12_PBE_KEYIVGEN,
                PKCS12_PBE_KEYIVGEN_EX,
                PKCS5_PBE_KEYIVGEN,
                PKCS5_PBE_KEYIVGEN_EX,
                // PKCS#12 key derivation
                PKCS12_KEY_GEN_ASC,
                PKCS12_KEY_GEN_ASC_EX,
                PKCS12_KEY_GEN_UNI,
                PKCS12_KEY_GEN_UNI_EX,
                PKCS12_KEY_GEN_UTF8,
                PKCS12_KEY_GEN_UTF8_EX);
    }

    private static final Supplier<List<IDetectionRule<AstNode>>> RULES =
            Memoize.of(OpenSSLEvpKdfPkcs12::buildRules);

    @Nonnull
    public static List<IDetectionRule<AstNode>> rules() {
        return RULES.get();
    }
}
