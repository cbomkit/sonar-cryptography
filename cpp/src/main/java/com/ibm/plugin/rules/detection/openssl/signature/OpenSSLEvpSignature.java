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
package com.ibm.plugin.rules.detection.openssl.signature;

import com.ibm.engine.language.cxx.CxxLanguageTranslation;
import com.ibm.engine.model.context.DigestContext;
import com.ibm.engine.model.context.SignatureContext;
import com.ibm.engine.model.factory.AlgorithmFactory;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.plugin.rules.detection.Memoize;
import com.ibm.plugin.rules.detection.openssl.digest.OpenSSLNameCanonicalizerFactory;
import com.ibm.plugin.translation.translator.contexts.CxxDigestContextTranslator;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import javax.annotation.Nonnull;

/**
 * Detection rules for OpenSSL signature operations.
 *
 * <p>These rules detect the signature algorithm fetched by name ({@code EVP_SIGNATURE_fetch}), the
 * RSA-PSS and MGF1 settings of a signing context, and the time-stamping signer digest given by
 * name. The signature algorithm of {@code EVP_DigestSign}/{@code EVP_PKEY_sign} and of the CMS,
 * PKCS#7 and OCSP signing functions is the type of the key given to them; those operations and the
 * digest they use are detected by {@code OpenSSLEvpKeyUsage}.
 */
@SuppressWarnings("java:S1192")
public final class OpenSSLEvpSignature {

    private static final String BUNDLE = "OpenSSL";

    // Signature algorithm fetched by name

    private static final IDetectionRule<AstNode> EVP_SIGNATURE_FETCH =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                    .forMethods("EVP_SIGNATURE_fetch")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .withMethodParameter("*")
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // RSA setters (signature-related)

    private static final IDetectionRule<AstNode> EVP_PKEY_CTX_SET_RSA_MGF1_MD_NAME =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                    .forMethods("EVP_PKEY_CTX_set_rsa_mgf1_md_name")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(
                            new OpenSSLNameCanonicalizerFactory(
                                    OpenSSLNameCanonicalizerFactory.DIGEST_NAMES))
                    .withMethodParameter("*")
                    .buildForContext(
                            new DigestContext(
                                    Map.of(
                                            CxxDigestContextTranslator.KIND,
                                            CxxDigestContextTranslator.MGF1_KIND)))
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, saltlen) is only accepted on an RSA-PSS signing
    // context

    private static final IDetectionRule<AstNode> EVP_PKEY_CTX_SET_RSA_PSS_SALTLEN =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                    .forMethods("EVP_PKEY_CTX_set_rsa_pss_saltlen")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RSA-PSS"))
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(new OpenSSLSaltLengthFactory())
                    .asChildOfParameterWithId(-1)
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // TS_CONF_set_signer_digest(conf, section, md, ctx): the time-stamping signer digest, given
    // by name

    private static final IDetectionRule<AstNode> TS_CONF_SET_SIGNER_DIGEST =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                    .forMethods("TS_CONF_set_signer_digest")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(
                            new OpenSSLNameCanonicalizerFactory(
                                    OpenSSLNameCanonicalizerFactory.DIGEST_NAMES))
                    .withMethodParameter("*")
                    .buildForContext(new DigestContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private OpenSSLEvpSignature() {
        // private
    }

    @Nonnull
    private static List<IDetectionRule<AstNode>> buildRules() {
        return List.of(
                // Fetch
                EVP_SIGNATURE_FETCH,
                // RSA setters
                EVP_PKEY_CTX_SET_RSA_MGF1_MD_NAME,
                EVP_PKEY_CTX_SET_RSA_PSS_SALTLEN,
                // RFC 3161 time-stamping
                TS_CONF_SET_SIGNER_DIGEST);
    }

    private static final Supplier<List<IDetectionRule<AstNode>>> RULES =
            Memoize.of(OpenSSLEvpSignature::buildRules);

    /**
     * The rules for the RSA-PSS settings of a signing context: its salt length and the digest of
     * its mask generation function, set on the context a digest sign or verify operation returns in
     * {@code pctx}.
     */
    @Nonnull
    public static List<IDetectionRule<AstNode>> signingContextRules() {
        return List.of(EVP_PKEY_CTX_SET_RSA_PSS_SALTLEN, EVP_PKEY_CTX_SET_RSA_MGF1_MD_NAME);
    }

    @Nonnull
    public static List<IDetectionRule<AstNode>> rules() {
        return RULES.get();
    }
}
