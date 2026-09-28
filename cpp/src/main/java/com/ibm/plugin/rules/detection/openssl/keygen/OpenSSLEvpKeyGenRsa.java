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

import com.ibm.engine.model.Size;
import com.ibm.engine.model.context.DigestContext;
import com.ibm.engine.model.context.KeyContext;
import com.ibm.engine.model.factory.KeySizeFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.plugin.rules.detection.Memoize;
import com.ibm.plugin.rules.detection.openssl.digest.OpenSSLEvpMessageDigest;
import com.ibm.plugin.rules.detection.openssl.digest.OpenSSLNameCanonicalizerFactory;
import com.ibm.plugin.rules.detection.openssl.signature.OpenSSLSaltLengthFactory;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.List;
import java.util.function.Supplier;
import javax.annotation.Nonnull;

/**
 * Detection rules for the RSA settings of an OpenSSL key generation context: the size of the key
 * and, for an RSA-PSS key, the digests and salt length it is restricted to. They apply to the calls
 * made on a context created by one of the rules of {@link OpenSSLEvpKeyGen}.
 */
public final class OpenSSLEvpKeyGenRsa {

    private static final String BUNDLE = "OpenSSL";

    private static final IDetectionRule<AstNode> EVP_RSA_KEYGEN_BITS =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_CTX_set_rsa_keygen_bits")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(new KeySizeFactory<>(Size.UnitType.BIT))
                    .buildForContext(new KeyContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // RSA-PSS keys: the digest, MGF1 digest and salt length the key is restricted to

    private static final IDetectionRule<AstNode> EVP_PKEY_CTX_SET_RSA_PSS_KEYGEN_MD =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods(
                            "EVP_PKEY_CTX_set_rsa_pss_keygen_md",
                            "EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .addDependingDetectionRules(OpenSSLEvpMessageDigest.rules())
                    .buildForContext(new KeyContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_PKEY_CTX_SET_RSA_PSS_KEYGEN_MD_NAME =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
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
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md_name")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(
                            new OpenSSLNameCanonicalizerFactory(
                                    OpenSSLNameCanonicalizerFactory.DIGEST_NAMES))
                    .buildForContext(new DigestContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_PKEY_CTX_SET_RSA_PSS_KEYGEN_SALTLEN =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_CTX_set_rsa_pss_keygen_saltlen")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(new OpenSSLSaltLengthFactory())
                    .buildForContext(new KeyContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private OpenSSLEvpKeyGenRsa() {
        // private
    }

    @Nonnull
    private static List<IDetectionRule<AstNode>> buildRules() {
        return List.of(
                EVP_RSA_KEYGEN_BITS,
                EVP_PKEY_CTX_SET_RSA_PSS_KEYGEN_MD,
                EVP_PKEY_CTX_SET_RSA_PSS_KEYGEN_MD_NAME,
                EVP_PKEY_CTX_SET_RSA_PSS_KEYGEN_MGF1_MD_NAME,
                EVP_PKEY_CTX_SET_RSA_PSS_KEYGEN_SALTLEN);
    }

    private static final Supplier<List<IDetectionRule<AstNode>>> RULES =
            Memoize.of(OpenSSLEvpKeyGenRsa::buildRules);

    @Nonnull
    public static List<IDetectionRule<AstNode>> rules() {
        return RULES.get();
    }
}
