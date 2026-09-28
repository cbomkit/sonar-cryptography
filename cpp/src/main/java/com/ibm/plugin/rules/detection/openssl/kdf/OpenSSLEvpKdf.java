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

import com.ibm.engine.model.context.DigestContext;
import com.ibm.engine.model.context.KeyDerivationFunctionContext;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.plugin.rules.detection.Memoize;
import com.ibm.plugin.rules.detection.openssl.digest.OpenSSLNameCanonicalizerFactory;
import com.ibm.plugin.rules.detection.openssl.legacy.OpenSSLNidLookupFactory;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.List;
import java.util.function.Supplier;
import java.util.stream.Stream;
import javax.annotation.Nonnull;

/**
 * Detection rules for OpenSSL Key Derivation Functions (KDFs).
 *
 * <p>The EVP_KDF API introduced in OpenSSL 3.0 selects the KDF by name in {@code EVP_KDF_fetch}
 * (PBKDF2, HKDF, SCRYPT, TLS1-PRF, ARGON2ID, ...). The digest used by the KDF is set on the context
 * created from the fetched KDF, through the {@code "digest"} entry of an {@code OSSL_PARAM} array
 * passed to {@code EVP_KDF_CTX_set_params} or {@code EVP_KDF_derive}:
 *
 * <pre>{@code
 * EVP_KDF *kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
 * EVP_KDF_CTX *kctx = EVP_KDF_CTX_new(kdf);
 * EVP_KDF_CTX_set_params(kctx, params); // params contains {"digest", "SHA256"}
 * }</pre>
 *
 * <p>HKDF, TLS1-PRF and scrypt can also be selected through the EVP_PKEY interface, by the key type
 * passed to {@code EVP_PKEY_CTX_new_id} or {@code EVP_PKEY_CTX_new_from_name}. The digest is then
 * set on that context by a KDF specific setter, found in {@link OpenSSLEvpKdfHkdf} and {@link
 * OpenSSLEvpKdfTls}:
 *
 * <pre>{@code
 * EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
 * EVP_PKEY_derive_init(pctx);
 * EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256());
 * }</pre>
 *
 * <p>The PKCS#12 and PKCS#5 password-based functions are in {@link OpenSSLEvpKdfPkcs12}; {@link
 * #rules()} includes them.
 */
public final class OpenSSLEvpKdf {

    private static final String BUNDLE = "OpenSSL";

    private static final IDetectionRule<AstNode> EVP_KDF_CTX_SET_PARAMS =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_KDF_CTX_set_params")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(
                            new OpenSSLParamsScannerFactory(
                                    "digest", OpenSSLNameCanonicalizerFactory.DIGEST_NAMES))
                    .buildForContext(new DigestContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_KDF_DERIVE =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_KDF_derive")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(
                            new OpenSSLParamsScannerFactory(
                                    "digest", OpenSSLNameCanonicalizerFactory.DIGEST_NAMES))
                    .buildForContext(new DigestContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_KDF_CTX_NEW =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_KDF_CTX_new")
                    .withMethodParameter("*")
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withDependingDetectionRules(List.of(EVP_KDF_CTX_SET_PARAMS, EVP_KDF_DERIVE));

    private static final IDetectionRule<AstNode> EVP_KDF_FETCH =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_KDF_fetch")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(
                            new OpenSSLNameCanonicalizerFactory(
                                    OpenSSLNameCanonicalizerFactory.KDF_NAMES))
                    .withMethodParameter("*")
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withDependingDetectionRules(List.of(EVP_KDF_CTX_NEW));

    // HKDF, TLS1-PRF and scrypt through the EVP_PKEY interface: the KDF is selected when the
    // context is created, and its digest is set on that context

    private static final List<IDetectionRule<AstNode>> EVP_PKEY_KDF_CONTEXT_RULES =
            Stream.of(OpenSSLEvpKdfHkdf.rules().stream(), OpenSSLEvpKdfTls.rules().stream())
                    .flatMap(i -> i)
                    .toList();

    private static final IDetectionRule<AstNode> EVP_PKEY_CTX_NEW_ID =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_CTX_new_id")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(
                            new OpenSSLNidLookupFactory(
                                    OpenSSLNidLookupFactory.PKEY_KDF_BY_CODE,
                                    OpenSSLNidLookupFactory.PKEY_KDF_BY_NAME))
                    .withMethodParameter("*")
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withDependingDetectionRules(EVP_PKEY_KDF_CONTEXT_RULES);

    private static final IDetectionRule<AstNode> EVP_PKEY_CTX_NEW_FROM_NAME =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_CTX_new_from_name")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(
                            new OpenSSLNameCanonicalizerFactory(
                                    OpenSSLNameCanonicalizerFactory.PKEY_KDF_NAMES, true))
                    .withMethodParameter("*")
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withDependingDetectionRules(EVP_PKEY_KDF_CONTEXT_RULES);

    private OpenSSLEvpKdf() {
        // private
    }

    @Nonnull
    private static List<IDetectionRule<AstNode>> buildRules() {
        return Stream.of(
                        OpenSSLEvpKdfPkcs12.rules().stream(),
                        Stream.of(EVP_KDF_FETCH, EVP_PKEY_CTX_NEW_ID, EVP_PKEY_CTX_NEW_FROM_NAME))
                .flatMap(i -> i)
                .toList();
    }

    private static final Supplier<List<IDetectionRule<AstNode>>> RULES =
            Memoize.of(OpenSSLEvpKdf::buildRules);

    @Nonnull
    public static List<IDetectionRule<AstNode>> rules() {
        return RULES.get();
    }
}
