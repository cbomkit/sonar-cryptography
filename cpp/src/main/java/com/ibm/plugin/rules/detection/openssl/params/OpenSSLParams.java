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
import com.ibm.engine.model.context.DigestContext;
import com.ibm.engine.model.context.IDetectionContext;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.plugin.rules.detection.Memoize;
import com.ibm.plugin.rules.detection.openssl.digest.OpenSSLNameCanonicalizerFactory;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
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
 * <p>The calls that take the parameters list {@link #digestRules()} or {@link #cipherRules()} as
 * the depending rules of their {@code OSSL_PARAM} argument.
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

    private OpenSSLParams() {
        // private
    }

    @Nonnull
    private static List<IDetectionRule<AstNode>> entryRules(
            @Nonnull List<String> keys,
            @Nonnull Map<String, String> names,
            @Nonnull IDetectionContext context) {
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

    private static final Supplier<List<IDetectionRule<AstNode>>> DIGEST_RULES =
            Memoize.of(
                    () ->
                            entryRules(
                                    DIGEST_KEYS,
                                    OpenSSLNameCanonicalizerFactory.DIGEST_NAMES,
                                    new DigestContext()));

    private static final Supplier<List<IDetectionRule<AstNode>>> CIPHER_RULES =
            Memoize.of(
                    () ->
                            entryRules(
                                    CIPHER_KEYS,
                                    OpenSSLNameCanonicalizerFactory.CIPHER_NAMES,
                                    new CipherContext()));

    /** The rules for the {@code "digest"} entry, detecting the digest it names. */
    @Nonnull
    public static List<IDetectionRule<AstNode>> digestRules() {
        return DIGEST_RULES.get();
    }

    /** The rules for the {@code "cipher"} entry, detecting the cipher it names. */
    @Nonnull
    public static List<IDetectionRule<AstNode>> cipherRules() {
        return CIPHER_RULES.get();
    }
}
