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
package com.ibm.plugin.rules.detection.openssl.params;

import com.ibm.engine.language.cxx.CxxLanguageTranslation;
import com.ibm.engine.model.context.CipherContext;
import com.ibm.engine.model.context.DetectionContext;
import com.ibm.engine.model.context.DigestContext;
import com.ibm.engine.rule.DetectionRuleSet;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.plugin.rules.detection.openssl.digest.OpenSSLNameCanonicalizerFactory;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import javax.annotation.Nonnull;

/**
 * Detection rules for the entries of an {@code OSSL_PARAM} array that name an algorithm: the {@code
 * "digest"} and {@code "cipher"} parameters of a KDF, MAC or DRBG context.
 *
 * <p>An entry is built by {@code OSSL_PARAM_construct_utf8_string(key, value, size)} or by the
 * {@code OSSL_PARAM_utf8_string(key, value, size)} macro (params.h), with the key given as a string
 * or as its name macro (core_names.h, e.g. {@code OSSL_KDF_PARAM_DIGEST} for {@code "digest"}). The
 * rules match the entry by its key and detect its value, wherever the entry is written to the array
 * passed to the call that takes the parameters:
 *
 * <pre>{@code
 * OSSL_PARAM params[] = {
 *     OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, "SHA256", 0),
 *     OSSL_PARAM_construct_end()
 * };
 * EVP_KDF_CTX_set_params(kctx, params);
 * }</pre>
 *
 * <p>The parameters can also be built with an {@code OSSL_PARAM_BLD} (param_build.h), whose entries
 * are pushed by {@code OSSL_PARAM_BLD_push_utf8_string(bld, key, value, size)} or {@code
 * OSSL_PARAM_BLD_push_utf8_ptr(bld, key, value, size)} and turned into the array by {@code
 * OSSL_PARAM_BLD_to_param(bld)}:
 *
 * <pre>{@code
 * OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
 * OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_KDF_PARAM_DIGEST, "SHA256", 0);
 * OSSL_PARAM *params = OSSL_PARAM_BLD_to_param(bld);
 * EVP_KDF_CTX_set_params(kctx, params);
 * }</pre>
 *
 * <p>The calls that take the parameters list {@link Digests} or {@link Ciphers} as the depending
 * rules of their {@code OSSL_PARAM} argument.
 */
public final class OpenSSLParams {

    private static final String BUNDLE = "OpenSSL";

    /** The functions and macros that build a UTF-8 string entry from a key, value and size. */
    private static final String[] UTF8_STRING_ENTRIES = {
        "OSSL_PARAM_construct_utf8_string", "OSSL_PARAM_utf8_string"
    };

    /** The keys of the digest entry: the string and the macros that stand for it. */
    private static final List<String> DIGEST_KEYS =
            List.of(
                    "\"digest\"",
                    "OSSL_ALG_PARAM_DIGEST",
                    "OSSL_KDF_PARAM_DIGEST",
                    "OSSL_MAC_PARAM_DIGEST",
                    "OSSL_DRBG_PARAM_DIGEST");

    /** The keys of the cipher entry: the string and the macros that stand for it. */
    private static final List<String> CIPHER_KEYS =
            List.of(
                    "\"cipher\"",
                    "OSSL_ALG_PARAM_CIPHER",
                    "OSSL_KDF_PARAM_CIPHER",
                    "OSSL_MAC_PARAM_CIPHER",
                    "OSSL_DRBG_PARAM_CIPHER");

    /** The functions that push a UTF-8 string entry from a key, value and size to a builder. */
    private static final String[] BUILDER_UTF8_STRING_ENTRIES = {
        "OSSL_PARAM_BLD_push_utf8_string", "OSSL_PARAM_BLD_push_utf8_ptr"
    };

    private OpenSSLParams() {
        // private
    }

    @Nonnull
    private static List<IDetectionRule<AstNode>> entryRules(
            @Nonnull List<String> keys,
            @Nonnull Map<String, String> names,
            @Nonnull DetectionContext context) {
        return keys.stream()
                .map(
                        key ->
                                new DetectionRuleBuilder<AstNode>()
                                        .createDetectionRule()
                                        .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                                        .forMethods(UTF8_STRING_ENTRIES)
                                        .withMethodParameter(key)
                                        .withMethodParameter("*")
                                        .shouldBeDetectedAs(
                                                new OpenSSLNameCanonicalizerFactory(names))
                                        .withMethodParameter("*")
                                        .buildForContext(context)
                                        .inBundle(() -> BUNDLE)
                                        .withoutDependingDetectionRules())
                .toList();
    }

    /**
     * The rules for the entries pushed to a builder, {@code OSSL_PARAM_BLD_push_utf8_string(bld,
     * key, value, size)}, matched by their key.
     */
    @Nonnull
    private static List<IDetectionRule<AstNode>> builderEntryRules(
            @Nonnull List<String> keys,
            @Nonnull Map<String, String> names,
            @Nonnull DetectionContext context) {
        return keys.stream()
                .map(
                        key ->
                                new DetectionRuleBuilder<AstNode>()
                                        .createDetectionRule()
                                        .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                                        .forMethods(BUILDER_UTF8_STRING_ENTRIES)
                                        .withMethodParameter("*")
                                        .withMethodParameter(key)
                                        .withMethodParameter("*")
                                        .shouldBeDetectedAs(
                                                new OpenSSLNameCanonicalizerFactory(names))
                                        .withMethodParameter("*")
                                        .buildForContext(context)
                                        .inBundle(() -> BUNDLE)
                                        .withoutDependingDetectionRules())
                .toList();
    }

    /**
     * The entry rules of an {@code OSSL_PARAM} array, and the rule for the array built by {@code
     * OSSL_PARAM_BLD_to_param(bld)}, which follows the builder to the entries pushed to it.
     */
    @Nonnull
    private static List<IDetectionRule<AstNode>> rules(
            @Nonnull List<String> keys,
            @Nonnull Map<String, String> names,
            @Nonnull DetectionContext context) {
        final IDetectionRule<AstNode> toParam =
                new DetectionRuleBuilder<AstNode>()
                        .createDetectionRule()
                        .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                        .forMethods("OSSL_PARAM_BLD_to_param")
                        .withMethodParameter("*")
                        .addDependingDetectionRules(builderEntryRules(keys, names, context))
                        .buildForContext(context)
                        .inBundle(() -> BUNDLE)
                        .withoutDependingDetectionRules();
        return Stream.concat(entryRules(keys, names, context).stream(), Stream.of(toParam))
                .toList();
    }

    /** The rules for the {@code "digest"} entry, detecting the digest it names. */
    public static final class Digests extends DetectionRuleSet<AstNode> {
        @Nonnull
        @Override
        protected List<IDetectionRule<AstNode>> buildRules() {
            return rules(
                    DIGEST_KEYS, OpenSSLNameCanonicalizerFactory.DIGEST_NAMES, new DigestContext());
        }
    }

    /** The rules for the {@code "cipher"} entry, detecting the cipher it names. */
    public static final class Ciphers extends DetectionRuleSet<AstNode> {
        @Nonnull
        @Override
        protected List<IDetectionRule<AstNode>> buildRules() {
            return rules(
                    CIPHER_KEYS, OpenSSLNameCanonicalizerFactory.CIPHER_NAMES, new CipherContext());
        }
    }
}
