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
package com.ibm.plugin.rules.detection.openssl.digest;

import com.ibm.engine.model.context.DigestContext;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.plugin.rules.detection.Memoize;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.List;
import java.util.function.Supplier;
import java.util.stream.Stream;
import javax.annotation.Nonnull;

/**
 * Detection rules for OpenSSL EVP message digest algorithm specifiers.
 *
 * <p>These rules detect calls to OpenSSL functions that return EVP_MD pointers, identifying the
 * specific hash algorithm being used. Each function (e.g., {@code EVP_sha256()}) maps to a known
 * digest algorithm name.
 *
 * <p>Per-family digest specifiers with multiple variants live in their own {@code
 * OpenSSLEvpMessageDigest<Family>} classes (MD, SHA-2, SHA-3/SHAKE, BLAKE2); this class holds the
 * remaining single-variant digests (SHA-1, RIPEMD, Whirlpool, SM3, combined/special digests) and
 * the generic EVP digest infrastructure (fetch, legacy lookup, init), and aggregates every family's
 * rules in {@link #rules()}.
 */
@SuppressWarnings("java:S1192")
public final class OpenSSLEvpMessageDigest {

    private static final String BUNDLE = "OpenSSL";

    private static final IDetectionRule<AstNode> EVP_SHA1 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_sha1")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SHA-1"))
                    .withoutParameters()
                    .buildForContext(new DigestContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_RIPEMD160 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_ripemd160")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RIPEMD160"))
                    .withoutParameters()
                    .buildForContext(new DigestContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_WHIRLPOOL =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_whirlpool")
                    .shouldBeDetectedAs(new ValueActionFactory<>("WHIRLPOOL"))
                    .withoutParameters()
                    .buildForContext(new DigestContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_SM3 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_sm3")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SM3"))
                    .withoutParameters()
                    .buildForContext(new DigestContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_MD5_SHA1 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_md5_sha1")
                    .shouldBeDetectedAs(new ValueActionFactory<>("MD5-SHA1"))
                    .withoutParameters()
                    .buildForContext(new DigestContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_MD_NULL =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_md_null")
                    .shouldBeDetectedAs(new ValueActionFactory<>("NULL"))
                    .withoutParameters()
                    .buildForContext(new DigestContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_MD_FETCH =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_MD_fetch")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(
                            new OpenSSLNameCanonicalizerFactory(
                                    OpenSSLNameCanonicalizerFactory.DIGEST_NAMES))
                    .withMethodParameter("*")
                    .buildForContext(new DigestContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_GET_DIGESTBYNAME =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_get_digestbyname")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(
                            new OpenSSLNameCanonicalizerFactory(
                                    OpenSSLNameCanonicalizerFactory.DIGEST_NAMES))
                    .buildForContext(new DigestContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_DIGEST_INIT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_DigestInit", "EVP_DigestInit_ex", "EVP_DigestInit_ex2")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DIGEST"))
                    .withAnyParameters()
                    .buildForContext(new DigestContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private OpenSSLEvpMessageDigest() {
        // private
    }

    @Nonnull
    private static List<IDetectionRule<AstNode>> buildRules() {
        return Stream.of(
                        OpenSSLEvpMessageDigestMd.rules().stream(),
                        OpenSSLEvpMessageDigestSha2.rules().stream(),
                        OpenSSLEvpMessageDigestSha3.rules().stream(),
                        OpenSSLEvpMessageDigestBlake2.rules().stream(),
                        directRules().stream())
                .flatMap(i -> i)
                .toList();
    }

    @Nonnull
    private static List<IDetectionRule<AstNode>> directRules() {
        return List.of(
                // SHA-1
                EVP_SHA1,
                // RIPEMD
                EVP_RIPEMD160,
                // Whirlpool
                EVP_WHIRLPOOL,
                // SM3 (Chinese National Standard)
                EVP_SM3,
                // Combined and Special Digests
                EVP_MD5_SHA1,
                EVP_MD_NULL,
                // MD fetch + legacy lookup + init_ex
                EVP_MD_FETCH,
                EVP_GET_DIGESTBYNAME,
                // EVP Digest init
                EVP_DIGEST_INIT);
    }

    private static final Supplier<List<IDetectionRule<AstNode>>> RULES =
            Memoize.of(OpenSSLEvpMessageDigest::buildRules);

    @Nonnull
    public static List<IDetectionRule<AstNode>> rules() {
        return RULES.get();
    }
}
