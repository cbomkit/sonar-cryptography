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
import com.sonar.cxx.sslr.api.AstNode;
import java.util.List;
import javax.annotation.Nonnull;

/**
 * Detection rules for OpenSSL EVP message digest algorithm specifiers.
 *
 * <p>These rules detect calls to OpenSSL functions that return EVP_MD pointers, identifying the
 * specific hash algorithm being used. Each function (e.g., {@code EVP_sha256()}) maps to a known
 * digest algorithm name.
 *
 * <p>Covers MD2, MD4, MD5, SHA-1, SHA-2, SHA-3, SHAKE, RIPEMD, Whirlpool, BLAKE2, SM3, and other
 * hash functions supported by OpenSSL.
 */
@SuppressWarnings("java:S1192")
public final class OpenSSLEvpMessageDigest {

    private static final String BUNDLE = "OpenSSL";

    // ====================================================================
    // MD Family
    // ====================================================================

    private static final IDetectionRule<AstNode> EVP_MD2 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_md2")
                    .shouldBeDetectedAs(new ValueActionFactory<>("MD2"))
                    .withoutParameters()
                    .buildForContext(new DigestContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_MD4 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_md4")
                    .shouldBeDetectedAs(new ValueActionFactory<>("MD4"))
                    .withoutParameters()
                    .buildForContext(new DigestContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_MD5 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_md5")
                    .shouldBeDetectedAs(new ValueActionFactory<>("MD5"))
                    .withoutParameters()
                    .buildForContext(new DigestContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_MDC2 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_mdc2")
                    .shouldBeDetectedAs(new ValueActionFactory<>("MDC2"))
                    .withoutParameters()
                    .buildForContext(new DigestContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // SHA-1
    // ====================================================================

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

    // ====================================================================
    // SHA-2 Family
    // ====================================================================

    private static final IDetectionRule<AstNode> EVP_SHA224 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_sha224")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SHA-224"))
                    .withoutParameters()
                    .buildForContext(new DigestContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_SHA256 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_sha256")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SHA-256"))
                    .withoutParameters()
                    .buildForContext(new DigestContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_SHA384 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_sha384")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SHA-384"))
                    .withoutParameters()
                    .buildForContext(new DigestContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_SHA512 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_sha512")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SHA-512"))
                    .withoutParameters()
                    .buildForContext(new DigestContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_SHA512_224 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_sha512_224")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SHA-512/224"))
                    .withoutParameters()
                    .buildForContext(new DigestContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_SHA512_256 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_sha512_256")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SHA-512/256"))
                    .withoutParameters()
                    .buildForContext(new DigestContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // SHA-3 Family
    // ====================================================================

    private static final IDetectionRule<AstNode> EVP_SHA3_224 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_sha3_224")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SHA3-224"))
                    .withoutParameters()
                    .buildForContext(new DigestContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_SHA3_256 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_sha3_256")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SHA3-256"))
                    .withoutParameters()
                    .buildForContext(new DigestContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_SHA3_384 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_sha3_384")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SHA3-384"))
                    .withoutParameters()
                    .buildForContext(new DigestContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_SHA3_512 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_sha3_512")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SHA3-512"))
                    .withoutParameters()
                    .buildForContext(new DigestContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // SHAKE (Extendable-Output Functions)
    // ====================================================================

    private static final IDetectionRule<AstNode> EVP_SHAKE128 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_shake128")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SHAKE128"))
                    .withoutParameters()
                    .buildForContext(new DigestContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_SHAKE256 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_shake256")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SHAKE256"))
                    .withoutParameters()
                    .buildForContext(new DigestContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // RIPEMD
    // ====================================================================

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

    // ====================================================================
    // Whirlpool
    // ====================================================================

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

    // ====================================================================
    // BLAKE2
    // ====================================================================

    private static final IDetectionRule<AstNode> EVP_BLAKE2B512 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_blake2b512")
                    .shouldBeDetectedAs(new ValueActionFactory<>("BLAKE2B-512"))
                    .withoutParameters()
                    .buildForContext(new DigestContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_BLAKE2S256 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_blake2s256")
                    .shouldBeDetectedAs(new ValueActionFactory<>("BLAKE2S-256"))
                    .withoutParameters()
                    .buildForContext(new DigestContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // SM3 (Chinese National Standard)
    // ====================================================================

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

    // ====================================================================
    // Combined and Special Digests
    // ====================================================================

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

    // ====================================================================
    // MD fetch + legacy lookup + init_ex
    // ====================================================================

    private static final IDetectionRule<AstNode> EVP_MD_FETCH =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_MD_fetch")
                    .shouldBeDetectedAs(new ValueActionFactory<>("MD-FETCH"))
                    .withAnyParameters()
                    .buildForContext(new DigestContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_GET_DIGESTBYNAME =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_get_digestbyname")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DIGEST-BY-NAME"))
                    .withAnyParameters()
                    .buildForContext(new DigestContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // ====================================================================
    // EVP Digest init
    // ====================================================================

    private static final IDetectionRule<AstNode> EVP_DIGEST_INIT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_DigestInit")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DIGEST"))
                    .withAnyParameters()
                    .buildForContext(new DigestContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_DIGEST_INIT_EX =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_DigestInit_ex")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DIGEST"))
                    .withAnyParameters()
                    .buildForContext(new DigestContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_DIGEST_INIT_EX2 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_DigestInit_ex2")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DIGEST"))
                    .withAnyParameters()
                    .buildForContext(new DigestContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private OpenSSLEvpMessageDigest() {
        // nothing
    }

    @Nonnull
    public static List<IDetectionRule<AstNode>> rules() {
        return List.of(
                // MD Family
                EVP_MD2,
                EVP_MD4,
                EVP_MD5,
                EVP_MDC2,
                // SHA-1
                EVP_SHA1,
                // SHA-2
                EVP_SHA224,
                EVP_SHA256,
                EVP_SHA384,
                EVP_SHA512,
                EVP_SHA512_224,
                EVP_SHA512_256,
                // SHA-3
                EVP_SHA3_224,
                EVP_SHA3_256,
                EVP_SHA3_384,
                EVP_SHA3_512,
                // SHAKE
                EVP_SHAKE128,
                EVP_SHAKE256,
                // RIPEMD
                EVP_RIPEMD160,
                // Whirlpool
                EVP_WHIRLPOOL,
                // BLAKE2
                EVP_BLAKE2B512,
                EVP_BLAKE2S256,
                // SM3
                EVP_SM3,
                // Combined/Special
                EVP_MD5_SHA1,
                EVP_MD_NULL,
                // MD fetch + legacy lookup
                EVP_MD_FETCH,
                EVP_GET_DIGESTBYNAME,
                // EVP Digest init
                EVP_DIGEST_INIT,
                EVP_DIGEST_INIT_EX,
                EVP_DIGEST_INIT_EX2);
    }
}
