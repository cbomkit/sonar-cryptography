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
package com.ibm.plugin.rules.detection.pycrypto.hash;

import static com.ibm.engine.detection.MethodMatcher.ANY;

import com.ibm.engine.model.AlgorithmParameter;
import com.ibm.engine.model.context.DigestContext;
import com.ibm.engine.model.factory.AlgorithmParameterFactory;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.plugin.rules.detection.Memoize;
import java.util.List;
import java.util.function.Supplier;
import javax.annotation.Nonnull;
import org.sonar.plugins.python.api.tree.Tree;

/**
 * Detection rules for PyCrypto / PyCryptodome hash functions that use the {@code .new()} factory
 * pattern (e.g. {@code Crypto.Hash.SHA512.new(data=b"...", truncate="256")}).
 *
 * <p>SHA512.new(data=None, truncate=None)
 *
 * <ul>
 *   <li>{@code data} — optional bytes to hash; ANY type, optional
 *   <li>{@code truncate} — optional truncation variant ("256" or "224"); type {@code str}, optional
 * </ul>
 *
 * <p>Both parameters are declared with {@code withNamedMethodParameter} so that keyword-argument
 * call sites (e.g. {@code SHA512.new(truncate="256")}) are handled correctly regardless of argument
 * order. The {@code truncate} value is captured as an {@link AlgorithmParameter} so that the
 * truncated variant (SHA-512/256 or SHA-512/224) can be reported.
 */
@SuppressWarnings("java:S1192")
public final class PycryptoCryptoHash {

    private PycryptoCryptoHash() {
        // private
    }

    /*
     * SHA512.new(data=None, truncate=None)
     *
     * Both Crypto and Cryptodome are supported (identical API).
     */
    private static final IDetectionRule<Tree> SHA512_NEW =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("Crypto.Hash.SHA512", "Cryptodome.Hash.SHA512")
                    .forMethods("new")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SHA512"))
                    .withNamedMethodParameter("data", ANY, /* optional */ true)
                    .withNamedMethodParameter("truncate", "str", /* optional */ true)
                    .shouldBeDetectedAs(
                            new AlgorithmParameterFactory<>(AlgorithmParameter.Kind.ANY))
                    .asChildOfParameterWithId(0)
                    .buildForContext(new DigestContext())
                    .inBundle(() -> "PyCrypto")
                    .withoutDependingDetectionRules();

    private static final Supplier<List<IDetectionRule<Tree>>> RULES =
            Memoize.of(PycryptoCryptoHash::buildRules);

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return RULES.get();
    }

    @Nonnull
    private static List<IDetectionRule<Tree>> buildRules() {
        return List.of(SHA512_NEW);
    }
}
