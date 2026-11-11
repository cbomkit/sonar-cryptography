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
import com.ibm.engine.model.context.CipherContext;
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
 * The symmetric half of OpenSSL's EVP interface, as C# reaches it through P/Invoke.
 *
 * <h2>Where the algorithm is written</h2>
 *
 * <p>An OpenSSL cipher is never named in the call that encrypts. {@code EVP_EncryptInit_ex(ctx,
 * type, impl, key, iv)} takes an {@code EVP_CIPHER *}, and that pointer comes from a second call
 * which is where the whole identity lives -- {@code EVP_aes_256_gcm()} is the algorithm, the key
 * length and the mode in one function name. This rule set therefore reads the cipher-returning
 * functions and not the {@code *Init*} family:
 *
 * <pre>{@code
 * EVP_EncryptInit_ex(ctx, Native.EVP_aes_256_gcm(), IntPtr.Zero, key, iv);
 * }</pre>
 *
 * <p>works because the C# frontend emits a call written as an argument as a statement in its own
 * right (see {@code CSharpTreeConverter#convertArgument}), so the inner call is a detection of its
 * own. The same holds for the shape managed wrappers actually use, where the handle is kept in a
 * field or a static:
 *
 * <pre>{@code
 * public static Cipher AES_256_GCM = new Cipher(Native.EVP_aes_256_gcm(), false);
 * }</pre>
 *
 * <p>(that line is openssl-net's, verbatim apart from the name).
 *
 * <p>{@code EVP_EncryptInit_ex} and its eleven siblings are deliberately <em>not</em> rules. The
 * only thing such a call adds is the direction, and a direction has nowhere to go: the engine
 * attaches a child to the node its own rule produced, and the algorithm belongs to a different
 * call. A rule there would have to emit a bare {@code Encrypt} component with no algorithm under
 * it, or re-read the cipher argument and report the algorithm a second time. Neither is worth the
 * direction, so the direction is not recorded for symmetric encryption.
 *
 * <h2>Why the receiver is {@code ANY}</h2>
 *
 * <p>These are {@code static extern} methods, so a call site is either bare -- {@code
 * EVP_aes_256_gcm()}, which the C# frontend gives an empty receiver -- or qualified with whatever
 * the P/Invoke holder is called: {@code Native}, {@code NativeMethods}, {@code Interop.Crypto}, a
 * name this plugin cannot know. {@code forObjectTypes} matches the literal receiver text (see
 * {@code CSharpLanguageTranslation#getInvokedObjectTypeString}), so no concrete type would match
 * either shape. The guard is the method name instead, and these names are safe to match on their
 * own: {@code EVP_aes_256_gcm} is not a word anyone uses for anything else, and a {@code DllImport}
 * declaration is a declaration rather than a call, so it is never detected.
 *
 * <h2>What each rule yields</h2>
 *
 * <ul>
 *   <li>{@code EVP_<cipher>()} -- the algorithm, the key length where the name states one, and the
 *       mode where the name states one. {@code EVP_aes_256_gcm} is AES-256-GCM; {@code EVP_rc4} is
 *       RC4 with no key length, because that one is set later with {@code
 *       EVP_CIPHER_CTX_set_key_length}.
 *   <li>{@code EVP_CIPHER_fetch(libctx, algorithm, properties)} and {@code
 *       EVP_get_cipherbyname(name)} -- the same, from the algorithm name string, when the string is
 *       a literal and names a cipher {@link OpenSslApi} knows. A name built at run time resolves to
 *       nothing.
 * </ul>
 */
public final class OpenSslCipher extends DetectionRuleSet<CSharpTree> {

    /** Marks the action of a cipher-returning {@code EVP_*} function. See {@link OpenSslApi}. */
    public static final String EVP_CIPHER_FUNCTION = "EVP_CIPHER_FUNCTION";

    @Nonnull
    private static CipherContext context() {
        return new CipherContext(Map.of(OpenSslDetectionRules.CONTEXT_KEY, "CIPHER"));
    }

    /**
     * Every {@code const EVP_CIPHER *EVP_<name>(void)} the table knows, in one rule.
     *
     * <p>One rule rather than one per function, because the value that tells them apart is the
     * method name itself, which the finding already carries: a detection's {@code
     * DetectionLocation} is built from the matched invocation and its first keyword is that
     * invocation's method name (see {@code CSharpTranslator#getDetectionContextFrom}; the CBOM
     * writer uses the same keyword as a finding's additional context). {@code
     * CSharpOpenSslContextTranslator} looks that name up in {@link OpenSslApi}, which is also where
     * this rule takes its method names from, so the matched set and the translated set cannot
     * diverge. Writing out 146 near-identical rules would say nothing more and would be 146 rules
     * evaluated against every statement of every C# file in a scan.
     */
    /**
     * One rule per function, built in a loop from the same table the translator reads -- every
     * EVP_CIPHER function OpenSSL ships, each carrying its own name as the action constant. Written
     * this way rather than as one rule over the whole name list so that the matched function
     * arrives as a value, which is how every other rule set in this project states what it found;
     * the alternative read the name back out of the detection location's keywords, a coupling
     * nothing else relies on.
     */
    @Nonnull
    private static List<IDetectionRule<CSharpTree>> cipher_functions() {
        final List<IDetectionRule<CSharpTree>> rules = new ArrayList<>();
        for (String function : OpenSslApi.cipherFunctionNames()) {
            rules.add(
                    new DetectionRuleBuilder<CSharpTree>()
                            .createDetectionRule()
                            .forObjectTypes(MethodMatcher.ANY)
                            .forMethods(function)
                            .shouldBeDetectedAs(new ValueActionFactory<>(function))
                            .withoutParameters()
                            .buildForContext(context())
                            .inBundle(() -> "OpenSsl")
                            .withoutDependingDetectionRules());
        }
        return List.copyOf(rules);
    }

    /**
     * {@code EVP_CIPHER_fetch(OSSL_LIB_CTX *ctx, const char *algorithm, const char *properties)}.
     *
     * <p>The 3.0 replacement for the static cipher functions, and the only one of the two that can
     * name an algorithm the table does not list. No action is declared, so the algorithm the string
     * resolves to <em>is</em> the finding; a string that resolves to nothing leaves the call
     * unreported rather than reporting a cipher named after it.
     */
    private static final IDetectionRule<CSharpTree> CIPHER_FETCH =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("EVP_CIPHER_fetch")
                    .withMethodParameter(MethodMatcher.ANY) // libctx
                    .withMethodParameter("string") // algorithm
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .withMethodParameter(MethodMatcher.ANY) // properties
                    .buildForContext(context())
                    .inBundle(() -> "OpenSsl")
                    .withoutDependingDetectionRules();

    /** {@code EVP_get_cipherbyname(const char *name)} -- the pre-3.0 lookup by name. */
    private static final IDetectionRule<CSharpTree> CIPHER_BY_NAME =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("EVP_get_cipherbyname")
                    .withMethodParameter("string")
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .buildForContext(context())
                    .inBundle(() -> "OpenSsl")
                    .withoutDependingDetectionRules();

    @Nonnull
    @Override
    protected List<IDetectionRule<CSharpTree>> buildRules() {
        return Stream.concat(cipher_functions().stream(), Stream.of(CIPHER_FETCH, CIPHER_BY_NAME))
                .toList();
    }
}
