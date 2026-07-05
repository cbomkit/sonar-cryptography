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
package com.ibm.plugin.rules.detection.bc.asymmetricblockcipher;

import com.ibm.engine.model.context.IDetectionContext;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.plugin.rules.detection.Memoize;
import java.util.List;
import java.util.function.Supplier;
import java.util.stream.Stream;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.sonar.plugins.java.api.tree.Tree;

public final class BcAsymmetricBlockCipher {

    private BcAsymmetricBlockCipher() {
        // nothing
    }

    private static final Supplier<List<IDetectionRule<Tree>>> RULES =
            Memoize.of(() -> buildRules(null, null));

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return RULES.get();
    }

    @Nonnull
    public static List<IDetectionRule<Tree>> rules(
            @Nullable IDetectionContext encodingDetectionValueContext,
            @Nullable IDetectionContext engineDetectionValueContext) {
        return encodingDetectionValueContext == null && engineDetectionValueContext == null
                ? RULES.get()
                : buildRules(encodingDetectionValueContext, engineDetectionValueContext);
    }

    @Nonnull
    private static List<IDetectionRule<Tree>> buildRules(
            @Nullable IDetectionContext encodingDetectionValueContext,
            @Nullable IDetectionContext engineDetectionValueContext) {
        return Stream.of(
                        BcPKCS1Encoding.rules(
                                encodingDetectionValueContext, engineDetectionValueContext)
                                .stream(),
                        BcOAEPEncoding.rules(
                                encodingDetectionValueContext, engineDetectionValueContext)
                                .stream(),
                        BcISO9796d1Encoding.rules(
                                encodingDetectionValueContext, engineDetectionValueContext)
                                .stream(),
                        BcAsymCipherEngine.rules(engineDetectionValueContext).stream())
                .flatMap(i -> i)
                .toList();
    }
}
