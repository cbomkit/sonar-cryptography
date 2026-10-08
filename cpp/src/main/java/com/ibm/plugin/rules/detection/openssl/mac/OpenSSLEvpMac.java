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
package com.ibm.plugin.rules.detection.openssl.mac;

import com.ibm.engine.language.cxx.CxxLanguageTranslation;
import com.ibm.engine.model.context.DigestContext;
import com.ibm.engine.model.context.MacContext;
import com.ibm.engine.rule.DetectionRuleSet;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.RuleSets;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.plugin.rules.detection.openssl.digest.OpenSSLNameCanonicalizerFactory;
import com.ibm.plugin.rules.detection.openssl.legacy.OpenSSLNidLookupFactory;
import com.ibm.plugin.rules.detection.openssl.params.OpenSSLParams;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.List;
import java.util.stream.Stream;
import javax.annotation.Nonnull;

/**
 * Detection rules for OpenSSL EVP MAC (Message Authentication Code) algorithms.
 *
 * <p>The EVP_MAC API introduced in OpenSSL 3.0 selects the MAC by name in {@code EVP_MAC_fetch}
 * (HMAC, CMAC, GMAC, KMAC-128, POLY1305, SIPHASH, ...). The digest of an HMAC and the cipher of a
 * CMAC or GMAC are set on the context created from the fetched MAC, through the {@code "digest"} or
 * {@code "cipher"} entry of an {@code OSSL_PARAM} array passed to {@code EVP_MAC_CTX_set_params} or
 * {@code EVP_MAC_init}:
 *
 * <pre>{@code
 * EVP_MAC *mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
 * EVP_MAC_CTX *ctx = EVP_MAC_CTX_new(mac);
 * EVP_MAC_init(ctx, key, keylen, params); // params contains {"digest", "SHA256"}
 * }</pre>
 *
 * <p>The password-based MAC of CRMF is reported with the MAC and the one-way function given to
 * {@code OSSL_CRMF_pbmp_new}.
 */
public final class OpenSSLEvpMac extends DetectionRuleSet<AstNode> {

    private static final String BUNDLE = "OpenSSL";

    private static final List<IDetectionRule<AstNode>> PARAMS_RULES =
            Stream.of(
                            RuleSets.rulesOf(OpenSSLParams.Digests.class).stream(),
                            RuleSets.rulesOf(OpenSSLParams.Ciphers.class).stream())
                    .flatMap(i -> i)
                    .toList();

    private static final IDetectionRule<AstNode> EVP_MAC_CTX_SET_PARAMS =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                    .forMethods("EVP_MAC_CTX_set_params")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .addDependingDetectionRules(PARAMS_RULES)
                    .buildForContext(new MacContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // EVP_MAC_init(ctx, key, keylen, params)
    private static final IDetectionRule<AstNode> EVP_MAC_INIT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                    .forMethods("EVP_MAC_init")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .addDependingDetectionRules(PARAMS_RULES)
                    .buildForContext(new MacContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_MAC_CTX_NEW =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                    .forMethods("EVP_MAC_CTX_new")
                    .withMethodParameter("*")
                    .buildForContext(new MacContext())
                    .inBundle(() -> BUNDLE)
                    .withDependingDetectionRules(List.of(EVP_MAC_CTX_SET_PARAMS, EVP_MAC_INIT));

    private static final IDetectionRule<AstNode> EVP_MAC_FETCH =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                    .forMethods("EVP_MAC_fetch")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(
                            new OpenSSLNameCanonicalizerFactory(
                                    OpenSSLNameCanonicalizerFactory.MAC_NAMES))
                    .withMethodParameter("*")
                    .buildForContext(new MacContext())
                    .inBundle(() -> BUNDLE)
                    .withDependingDetectionRules(List.of(EVP_MAC_CTX_NEW));

    // EVP_Q_mac(libctx, name, propq, subalg, params, key, keylen, data, datalen, out, outsize,
    // outlen): the MAC, and the digest of an HMAC or the cipher of a CMAC or GMAC
    private static final IDetectionRule<AstNode> EVP_Q_MAC =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                    .forMethods("EVP_Q_mac")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(
                            new OpenSSLNameCanonicalizerFactory(
                                    OpenSSLNameCanonicalizerFactory.MAC_NAMES))
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(new OpenSSLMacSubAlgorithmFactory())
                    .asChildOfParameterWithId(-1)
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .buildForContext(new MacContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // OSSL_CRMF_pbmp_new(libctx, slen, owfnid, itercnt, macnid): the password-based MAC of
    // CRMF (RFC 4211) derives its key with the one-way function owfnid and computes the MAC
    // macnid

    private static final IDetectionRule<AstNode> OSSL_CRMF_PBMP_NEW_MAC =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                    .forMethods("OSSL_CRMF_pbmp_new")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(
                            new OpenSSLNidLookupFactory(
                                    OpenSSLNidLookupFactory.HMAC_BY_CODE,
                                    OpenSSLNidLookupFactory.HMAC_BY_NAME))
                    .buildForContext(new MacContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> OSSL_CRMF_PBMP_NEW_OWF =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                    .forMethods("OSSL_CRMF_pbmp_new")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(
                            new OpenSSLNidLookupFactory(
                                    OpenSSLNidLookupFactory.DIGEST_BY_CODE,
                                    OpenSSLNidLookupFactory.DIGEST_BY_NAME))
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .buildForContext(new DigestContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    @Nonnull
    @Override
    protected List<IDetectionRule<AstNode>> buildRules() {
        return List.of(EVP_MAC_FETCH, EVP_Q_MAC, OSSL_CRMF_PBMP_NEW_MAC, OSSL_CRMF_PBMP_NEW_OWF);
    }
}
