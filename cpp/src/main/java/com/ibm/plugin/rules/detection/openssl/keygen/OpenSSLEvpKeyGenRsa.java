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

import com.ibm.engine.language.cxx.CxxLanguageTranslation;
import com.ibm.engine.model.Size;
import com.ibm.engine.model.context.DigestContext;
import com.ibm.engine.model.context.KeyContext;
import com.ibm.engine.model.context.SignatureContext;
import com.ibm.engine.model.factory.KeySizeFactory;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.DetectionRuleSet;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.RuleSets;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.plugin.rules.detection.DerivedDetectionRules;
import com.ibm.plugin.rules.detection.openssl.OpenSSLSizeFactory;
import com.ibm.plugin.rules.detection.openssl.digest.OpenSSLEvpMessageDigest;
import com.ibm.plugin.rules.detection.openssl.digest.OpenSSLNameCanonicalizerFactory;
import com.ibm.plugin.rules.detection.openssl.signature.OpenSSLSaltLengthFactory;
import com.ibm.plugin.translation.translator.contexts.CxxDigestContextTranslator;
import com.ibm.plugin.translation.translator.contexts.CxxSignatureContextTranslator;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.List;
import java.util.Map;
import javax.annotation.Nonnull;

/**
 * Detection rules for the RSA settings of an OpenSSL key generation context: the size of the key
 * and, for an RSA-PSS key, the digests and salt length it is restricted to. They apply to the calls
 * made on a context created by one of the rules of {@link OpenSSLEvpKeyGen}.
 */
public final class OpenSSLEvpKeyGenRsa extends DetectionRuleSet<AstNode> {

    private static final String BUNDLE = "OpenSSL";

    private static final IDetectionRule<AstNode> EVP_RSA_KEYGEN_BITS =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                    .forMethods("EVP_PKEY_CTX_set_rsa_keygen_bits")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(
                            new OpenSSLSizeFactory(new KeySizeFactory<>(Size.UnitType.BIT)))
                    .buildForContext(new KeyContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // RSA-PSS keys: the digest, MGF1 digest and salt length the key is restricted to; the MGF1
    // digest is reported as MGF1 with that digest

    private static final IDetectionRule<AstNode> EVP_PKEY_CTX_SET_RSA_PSS_KEYGEN_MD =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                    .forMethods("EVP_PKEY_CTX_set_rsa_pss_keygen_md")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .addDependingDetectionRules(RuleSets.rulesOf(OpenSSLEvpMessageDigest.class))
                    .buildForContext(new KeyContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_PKEY_CTX_SET_RSA_PSS_KEYGEN_MGF1_MD =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                    .forMethods("EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .addDependingDetectionRules(
                            RuleSets.rulesOf(OpenSSLEvpMessageDigest.Mgf1.class))
                    .buildForContext(new KeyContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_PKEY_CTX_SET_RSA_PSS_KEYGEN_MD_NAME =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
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

    private static final IDetectionRule<AstNode> EVP_PKEY_CTX_SET_RSA_PSS_KEYGEN_MGF1_MD_NAME =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                    .forMethods("EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md_name")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(
                            new OpenSSLNameCanonicalizerFactory(
                                    OpenSSLNameCanonicalizerFactory.DIGEST_NAMES))
                    .buildForContext(
                            new DigestContext(
                                    Map.of(
                                            CxxDigestContextTranslator.KIND,
                                            CxxDigestContextTranslator.MGF1_KIND)))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_PKEY_CTX_SET_RSA_PSS_KEYGEN_SALTLEN =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                    .forMethods("EVP_PKEY_CTX_set_rsa_pss_keygen_saltlen")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(new OpenSSLSaltLengthFactory())
                    .buildForContext(new KeyContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    /**
     * The RSA-PSS key generation settings as detections of their own, for a key generation context
     * created elsewhere: each setting is only accepted on an RSA-PSS key generation context, so it
     * reports RSA-PSS with the digest, MGF1 digest or salt length it restricts the key to. A
     * setting reported with the key generated in the analyzed code is not reported again (see
     * {@link DerivedDetectionRules}).
     */
    public static final class KeyGenerationSettings extends DetectionRuleSet<AstNode> {
        @Nonnull
        @Override
        protected List<IDetectionRule<AstNode>> buildRules() {
            return List.of(
                    rsaPss(EVP_PKEY_CTX_SET_RSA_PSS_KEYGEN_MD, Map.of()),
                    rsaPss(EVP_PKEY_CTX_SET_RSA_PSS_KEYGEN_MGF1_MD, Map.of()),
                    rsaPss(
                            EVP_PKEY_CTX_SET_RSA_PSS_KEYGEN_MD_NAME,
                            Map.of(
                                    CxxSignatureContextTranslator.KIND,
                                    CxxSignatureContextTranslator.DIGEST_NAME_KIND)),
                    rsaPss(
                            EVP_PKEY_CTX_SET_RSA_PSS_KEYGEN_MGF1_MD_NAME,
                            Map.of(
                                    CxxSignatureContextTranslator.KIND,
                                    CxxSignatureContextTranslator.MGF1_DIGEST_NAME_KIND)),
                    rsaPss(EVP_PKEY_CTX_SET_RSA_PSS_KEYGEN_SALTLEN, Map.of()));
        }
    }

    @Nonnull
    private static IDetectionRule<AstNode> rsaPss(
            @Nonnull IDetectionRule<AstNode> setting, @Nonnull Map<String, String> properties) {
        return DerivedDetectionRules.withAction(
                setting, new ValueActionFactory<>("RSA-PSS"), new SignatureContext(properties));
    }

    @Nonnull
    @Override
    protected List<IDetectionRule<AstNode>> buildRules() {
        return List.of(
                EVP_RSA_KEYGEN_BITS,
                EVP_PKEY_CTX_SET_RSA_PSS_KEYGEN_MD,
                EVP_PKEY_CTX_SET_RSA_PSS_KEYGEN_MGF1_MD,
                EVP_PKEY_CTX_SET_RSA_PSS_KEYGEN_MD_NAME,
                EVP_PKEY_CTX_SET_RSA_PSS_KEYGEN_MGF1_MD_NAME,
                EVP_PKEY_CTX_SET_RSA_PSS_KEYGEN_SALTLEN);
    }
}
