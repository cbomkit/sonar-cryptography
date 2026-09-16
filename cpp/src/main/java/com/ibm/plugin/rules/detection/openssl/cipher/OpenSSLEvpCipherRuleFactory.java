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

import com.ibm.engine.model.context.CipherContext;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.ArrayList;
import java.util.List;
import javax.annotation.Nonnull;

/**
 * Builds the {@code EVP_CIPHER}-returning detection rules shared by every OpenSSL cipher family
 * (AES, ARIA, Camellia, DES, and the legacy variants): a zero-argument function that always
 * resolves to a fixed cipher-spec label.
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
     * One {@code functionNames -> label} entry for a legacy (pre-EVP) cipher call, e.g. {@code
     * ["DES_ncbc_encrypt", "DES_cbc_encrypt"] -> "DES-CBC"}. Legacy calls take runtime buffer/key
     * arguments the detection rule doesn't constrain, unlike the zero-argument EVP getters.
     */
    public record LegacyEntry(@Nonnull List<String> functionNames, @Nonnull String label) {
        public LegacyEntry(@Nonnull String functionName, @Nonnull String label) {
            this(List.of(functionName), label);
        }
    }

    /** Builds one detection rule per legacy entry, in list order. */
    @Nonnull
    public static List<IDetectionRule<AstNode>> buildLegacy(
            @Nonnull String bundle, @Nonnull List<LegacyEntry> entries) {
        List<IDetectionRule<AstNode>> rules = new ArrayList<>(entries.size());
        for (LegacyEntry entry : entries) {
            rules.add(
                    new DetectionRuleBuilder<AstNode>()
                            .createDetectionRule()
                            .forObjectTypes("*")
                            .forMethods(entry.functionNames().toArray(new String[0]))
                            .shouldBeDetectedAs(new ValueActionFactory<>(entry.label()))
                            .withAnyParameters()
                            .buildForContext(new CipherContext())
                            .inBundle(() -> bundle)
                            .withoutDependingDetectionRules());
        }
        return rules;
    }
}
