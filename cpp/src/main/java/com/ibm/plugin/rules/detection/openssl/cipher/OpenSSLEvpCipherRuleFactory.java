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
package com.ibm.plugin.rules.detection.openssl.cipher;

import com.ibm.engine.model.Size;
import com.ibm.engine.model.context.CipherContext;
import com.ibm.engine.model.factory.KeySizeFactory;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;
import java.util.function.Supplier;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

/**
 * Builds the cipher detection rules shared by every OpenSSL cipher family: the {@code
 * EVP_CIPHER}-returning functions (AES, ARIA, Camellia, DES, ...), which take no argument and
 * always resolve to a fixed cipher-spec label, and the legacy (pre-EVP) key setup and encryption
 * functions of each cipher.
 */
public final class OpenSSLEvpCipherRuleFactory {

    private OpenSSLEvpCipherRuleFactory() {
        // private
    }

    /** One {@code functionName -> label} entry, e.g. {@code "EVP_aes_128_cbc" -> "AES-128-CBC"}. */
    public record Entry(@Nonnull String functionName, @Nonnull String label) {}

    /** Builds one detection rule per entry, in list order. */
    @Nonnull
    public static List<IDetectionRule<AstNode>> build(
            @Nonnull String bundle, @Nonnull List<Entry> entries) {
        List<IDetectionRule<AstNode>> rules = new ArrayList<>(entries.size());
        for (Entry entry : entries) {
            rules.add(
                    new DetectionRuleBuilder<AstNode>()
                            .createDetectionRule()
                            .forObjectTypes("*")
                            .forMethods(entry.functionName())
                            .shouldBeDetectedAs(new ValueActionFactory<>(entry.label()))
                            .withoutParameters()
                            .buildForContext(new CipherContext())
                            .inBundle(() -> bundle)
                            .withoutDependingDetectionRules());
        }
        return rules;
    }

    /**
     * The context kind of the legacy cipher rules: their labels name a cipher and its mode, while
     * the key length is set by the key setup function of the key they use.
     */
    public static final String LEGACY = "LEGACY";

    /**
     * One {@code functionNames -> label} entry for a legacy (pre-EVP) cipher call, e.g. {@code
     * ["DES_ncbc_encrypt", "DES_cbc_encrypt"] -> "DES-CBC"}, with the number of arguments of the
     * functions (which share one prototype) and:
     *
     * <ul>
     *   <li>for a key setup function, the argument that gives the key size and its unit (e.g. the
     *       {@code bits} of {@code AES_set_encrypt_key}, the {@code len} in bytes of {@code
     *       BF_set_key}); {@code keySizeParameter} is -1 when there is none;
     *   <li>for an encryption function, the argument that gives the key schedule set up by a key
     *       setup function of the same family (e.g. the {@code key} of {@code AES_cbc_encrypt});
     *       {@code keyParameter} is -1 when the key is not followed, as for a cipher whose key
     *       length is fixed.
     * </ul>
     */
    public record LegacyEntry(
            @Nonnull List<String> functionNames,
            @Nonnull String label,
            int parameterCount,
            int keySizeParameter,
            @Nullable Size.UnitType keySizeUnit,
            int keyParameter) {

        public LegacyEntry(
                @Nonnull String functionName, @Nonnull String label, int parameterCount) {
            this(List.of(functionName), label, parameterCount);
        }

        public LegacyEntry(
                @Nonnull List<String> functionNames, @Nonnull String label, int parameterCount) {
            this(functionNames, label, parameterCount, -1, null, -1);
        }

        public LegacyEntry(
                @Nonnull String functionName,
                @Nonnull String label,
                int parameterCount,
                int keySizeParameter,
                @Nonnull Size.UnitType keySizeUnit) {
            this(List.of(functionName), label, parameterCount, keySizeParameter, keySizeUnit, -1);
        }

        /** The same entry, whose key schedule is the argument at the given index. */
        @Nonnull
        public LegacyEntry keyAt(int parameter) {
            return new LegacyEntry(
                    functionNames, label, parameterCount, keySizeParameter, keySizeUnit, parameter);
        }

        private boolean isKeySetup() {
            return keySizeParameter >= 0;
        }
    }

    /**
     * Builds one detection rule per legacy entry, in list order. The key size, when the entry has
     * one, is reported as a child of the detected cipher. The key schedule argument of an
     * encryption function is followed to the key setup functions of the same entries, so that the
     * encryption reports the key size its key was set up with:
     *
     * <pre>{@code
     * AES_set_encrypt_key(userKey, 256, &key);
     * AES_cbc_encrypt(in, out, length, &key, iv, AES_ENCRYPT); // AES-256-CBC
     * }</pre>
     */
    @Nonnull
    public static List<IDetectionRule<AstNode>> buildLegacy(
            @Nonnull String bundle, @Nonnull List<LegacyEntry> entries) {
        final List<IDetectionRule<AstNode>> keySetups =
                entries.stream()
                        .filter(LegacyEntry::isKeySetup)
                        .map(entry -> buildLegacy(bundle, entry, List.of()))
                        .toList();
        final List<IDetectionRule<AstNode>> rules = new ArrayList<>(entries.size());
        int keySetup = 0;
        for (LegacyEntry entry : entries) {
            rules.add(
                    entry.isKeySetup()
                            ? keySetups.get(keySetup++)
                            : buildLegacy(bundle, entry, keySetups));
        }
        return rules;
    }

    @Nonnull
    private static IDetectionRule<AstNode> buildLegacy(
            @Nonnull String bundle,
            @Nonnull LegacyEntry entry,
            @Nonnull List<IDetectionRule<AstNode>> keySetups) {
        final IDetectionRule.ParametersTypeBuilder<AstNode> call =
                new DetectionRuleBuilder<AstNode>()
                        .createDetectionRule()
                        .forObjectTypes("*")
                        .forMethods(entry.functionNames().toArray(new String[0]))
                        .shouldBeDetectedAs(new ValueActionFactory<>(entry.label()));
        final CipherContext context = new CipherContext(Map.of("kind", LEGACY));
        if (entry.parameterCount() == 0) {
            return call.withoutParameters()
                    .buildForContext(context)
                    .inBundle(() -> bundle)
                    .withoutDependingDetectionRules();
        }
        Chain chain = Chain.of(call.withMethodParameter("*"));
        for (int i = 0; i < entry.parameterCount(); i++) {
            if (i > 0) {
                chain = Chain.of(chain.next().get());
            }
            if (i == entry.keySizeParameter()) {
                chain =
                        Chain.of(
                                chain.current()
                                        .shouldBeDetectedAs(
                                                new KeySizeFactory<>(
                                                        Objects.requireNonNull(
                                                                entry.keySizeUnit())))
                                        .asChildOfParameterWithId(-1));
            } else if (i == entry.keyParameter() && !keySetups.isEmpty()) {
                chain = Chain.of(chain.current().addDependingDetectionRules(keySetups));
            }
        }
        return chain.build().apply(context).inBundle(() -> bundle).withoutDependingDetectionRules();
    }

    /**
     * The rule being built after one of its parameters: the parameter itself, or the parameter with
     * a value or depending rules, from which the next parameter is added or the rule built.
     */
    private record Chain(
            @Nullable IDetectionRule.ParametersFactoryBuilder<AstNode> current,
            @Nonnull Supplier<IDetectionRule.ParametersFactoryBuilder<AstNode>> next,
            @Nonnull
                    Function<CipherContext, IDetectionRule.AddBundleDetectionRuleBuilder<AstNode>>
                            build) {

        @Nonnull
        static Chain of(@Nonnull IDetectionRule.ParametersFactoryBuilder<AstNode> parameter) {
            return new Chain(
                    parameter,
                    () -> parameter.withMethodParameter("*"),
                    parameter::buildForContext);
        }

        @Nonnull
        static Chain of(
                @Nonnull IDetectionRule.ParametersDependingRulesBuilder<AstNode> parameter) {
            return new Chain(
                    null, () -> parameter.withMethodParameter("*"), parameter::buildForContext);
        }

        @Nonnull
        static Chain of(
                @Nonnull IDetectionRule.ParametersFinalDetectionRuleBuilder<AstNode> parameter) {
            return new Chain(
                    null, () -> parameter.withMethodParameter("*"), parameter::buildForContext);
        }

        @Nonnull
        @Override
        public IDetectionRule.ParametersFactoryBuilder<AstNode> current() {
            return Objects.requireNonNull(current, "a parameter holds one value or rule list");
        }
    }
}
