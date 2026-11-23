/*
 * Sonar Cryptography Plugin
 * Copyright (C) 2026 PQCA
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
package com.ibm.plugin.rules.detection.openssl;

import com.ibm.engine.detection.MethodMatcher;
import com.ibm.engine.language.csharp.tree.CSharpTree;
import com.ibm.engine.model.context.DigestContext;
import com.ibm.engine.model.context.MacContext;
import com.ibm.engine.model.factory.AlgorithmFactory;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.DetectionRuleSet;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import javax.annotation.Nonnull;

/**
 * OpenSSL's message digests and HMAC, as C# reaches them through P/Invoke.
 *
 * <p>The digests follow the ciphers exactly (see {@link OpenSslCipher} for why the receiver is
 * {@code ANY} and why one rule carries every function name): the identity is in the name of the
 * function that returns the {@code EVP_MD *}, so {@code EVP_sha3_256()} is the finding and {@code
 * EVP_DigestInit_ex(ctx, md, impl)} is not a rule -- it names no algorithm.
 *
 * <p>HMAC is the one place where a rule is worth having without an algorithm under it. {@code
 * HMAC(evp_md, key, key_len, data, data_len, md, md_len)} states that a keyed MAC is computed,
 * which is a fact about the code that the digest function alone does not carry: {@code
 * EVP_sha256()} appears in signing, in PBKDF2 and in a bare hash just as much. The digest is
 * <em>not</em> read out of the first argument, and that is deliberate. In real wrappers it is not
 * resolvable anyway -- openssl-net writes {@code Native.HMAC(digest.Handle, key, key.Length, ...)},
 * a field access on an object -- and where it is written inline as {@code HMAC(EVP_sha256(), ...)}
 * the inner call is already a digest finding of its own, so reading it here as well would report
 * SHA-256 twice for one line. The result is an {@code HMAC} component beside the digest it uses,
 * rather than one combined component or two copies of the digest.
 */
public final class OpenSslDigest extends DetectionRuleSet<CSharpTree> {

    /** Marks the action of a digest-returning {@code EVP_*} function. See {@link OpenSslApi}. */
    public static final String EVP_MD_FUNCTION = "EVP_MD_FUNCTION";

    /** Marks a keyed-MAC call of the {@code HMAC} family. */
    public static final String HMAC = "HMAC";

    @Nonnull
    private static DigestContext digestContext() {
        return new DigestContext(Map.of(OpenSslDetectionRules.CONTEXT_KEY, "DIGEST"));
    }

    @Nonnull
    private static MacContext macContext() {
        return new MacContext(Map.of(OpenSslDetectionRules.CONTEXT_KEY, "HMAC"));
    }

    @Nonnull
    private static MacContext macFetchContext() {
        return new MacContext(Map.of(OpenSslDetectionRules.CONTEXT_KEY, "MAC_FETCH"));
    }

    /**
     * {@code EVP_MAC_fetch(OSSL_LIB_CTX *libctx, const char *algorithm, const char *properties)}.
     *
     * <p>The 3.0 way of asking for a MAC, and the only place in the OpenSSL API where a MAC is
     * named rather than implied by a context. It is the exact counterpart of {@code EVP_KDF_fetch},
     * which this rule set already read -- a MAC named by string was the one half of that pair that
     * was missing. {@code HMAC_*} stays separate: those name the MAC in the function itself.
     *
     * <p>Which names become a node is decided in the translator against a closed set, so {@code
     * EVP_MAC_fetch(ctx, "GMAC", null)} -- a MAC this project has no algorithm node for -- reports
     * nothing rather than something adjacent.
     */
    private static final IDetectionRule<CSharpTree> MAC_FETCH =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("EVP_MAC_fetch")
                    .withMethodParameter(MethodMatcher.ANY) // libctx
                    .withMethodParameter("string") // algorithm
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .withMethodParameter(MethodMatcher.ANY) // properties
                    .buildForContext(macFetchContext())
                    .inBundle(() -> "OpenSsl")
                    .withoutDependingDetectionRules();

    /** Every {@code const EVP_MD *EVP_<name>(void)} the table knows, in one rule. */
    /**
     * One rule per function, built in a loop from the same table the translator reads -- every
     * EVP_MD function OpenSSL ships, each carrying its own name as the action constant. Written
     * this way rather than as one rule over the whole name list so that the matched function
     * arrives as a value, which is how every other rule set in this project states what it found;
     * the alternative read the name back out of the detection location's keywords, a coupling
     * nothing else relies on.
     */
    @Nonnull
    private static List<IDetectionRule<CSharpTree>> digest_functions() {
        final List<IDetectionRule<CSharpTree>> rules = new ArrayList<>();
        for (String function : OpenSslApi.digestFunctionNames()) {
            rules.add(
                    new DetectionRuleBuilder<CSharpTree>()
                            .createDetectionRule()
                            .forObjectTypes(MethodMatcher.ANY)
                            .forMethods(function)
                            .shouldBeDetectedAs(new ValueActionFactory<>(function))
                            .withoutParameters()
                            .buildForContext(digestContext())
                            .inBundle(() -> "OpenSsl")
                            .withoutDependingDetectionRules());
        }
        return List.copyOf(rules);
    }

    /** {@code EVP_MD_fetch(OSSL_LIB_CTX *ctx, const char *algorithm, const char *properties)}. */
    private static final IDetectionRule<CSharpTree> DIGEST_FETCH =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("EVP_MD_fetch")
                    .withMethodParameter(MethodMatcher.ANY) // libctx
                    .withMethodParameter("string") // algorithm
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .withMethodParameter(MethodMatcher.ANY) // properties
                    .buildForContext(digestContext())
                    .inBundle(() -> "OpenSsl")
                    .withoutDependingDetectionRules();

    /** {@code EVP_get_digestbyname(const char *name)} -- the pre-3.0 lookup by name. */
    private static final IDetectionRule<CSharpTree> DIGEST_BY_NAME =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("EVP_get_digestbyname")
                    .withMethodParameter("string")
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .buildForContext(digestContext())
                    .inBundle(() -> "OpenSsl")
                    .withoutDependingDetectionRules();

    /**
     * {@code HMAC(evp_md, key, key_len, data, data_len, md, md_len)} -- the one-shot form.
     *
     * <p>Seven positional parameters, so the arity alone separates this from the two {@code
     * HMAC_Init} rules below even though all three would otherwise accept the same shape.
     */
    private static final IDetectionRule<CSharpTree> HMAC_ONE_SHOT =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("HMAC")
                    .shouldBeDetectedAs(new ValueActionFactory<>(HMAC))
                    .withMethodParameter(MethodMatcher.ANY) // evp_md
                    .withMethodParameter(MethodMatcher.ANY) // key
                    .withMethodParameter(MethodMatcher.ANY) // key_len
                    .withMethodParameter(MethodMatcher.ANY) // data
                    .withMethodParameter(MethodMatcher.ANY) // data_len
                    .withMethodParameter(MethodMatcher.ANY) // md
                    .withMethodParameter(MethodMatcher.ANY) // md_len
                    .buildForContext(macContext())
                    .inBundle(() -> "OpenSsl")
                    .withoutDependingDetectionRules();

    /** {@code HMAC_Init_ex(ctx, key, key_len, md, impl)} -- deprecated in 3.0, still common. */
    private static final IDetectionRule<CSharpTree> HMAC_INIT_EX =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("HMAC_Init_ex")
                    .shouldBeDetectedAs(new ValueActionFactory<>(HMAC))
                    .withMethodParameter(MethodMatcher.ANY) // ctx
                    .withMethodParameter(MethodMatcher.ANY) // key
                    .withMethodParameter(MethodMatcher.ANY) // key_len
                    .withMethodParameter(MethodMatcher.ANY) // md
                    .withMethodParameter(MethodMatcher.ANY) // impl
                    .buildForContext(macContext())
                    .inBundle(() -> "OpenSsl")
                    .withoutDependingDetectionRules();

    /** {@code HMAC_Init(ctx, key, key_len, md)} -- deprecated in 1.1.0. */
    private static final IDetectionRule<CSharpTree> HMAC_INIT =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("HMAC_Init")
                    .shouldBeDetectedAs(new ValueActionFactory<>(HMAC))
                    .withMethodParameter(MethodMatcher.ANY) // ctx
                    .withMethodParameter(MethodMatcher.ANY) // key
                    .withMethodParameter(MethodMatcher.ANY) // key_len
                    .withMethodParameter(MethodMatcher.ANY) // md
                    .buildForContext(macContext())
                    .inBundle(() -> "OpenSsl")
                    .withoutDependingDetectionRules();

    @Nonnull
    @Override
    protected List<IDetectionRule<CSharpTree>> buildRules() {
        return Stream.concat(
                        digest_functions().stream(),
                        Stream.of(
                                DIGEST_FETCH,
                                DIGEST_BY_NAME,
                                HMAC_ONE_SHOT,
                                HMAC_INIT_EX,
                                HMAC_INIT,
                                MAC_FETCH))
                .toList();
    }
}
