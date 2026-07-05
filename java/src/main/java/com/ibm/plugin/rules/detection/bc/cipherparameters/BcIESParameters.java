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
package com.ibm.plugin.rules.detection.bc.cipherparameters;

import static com.ibm.plugin.rules.detection.TypeShortcuts.BYTE_ARRAY_TYPE;

import com.ibm.engine.model.Size;
import com.ibm.engine.model.context.AlgorithmParameterContext;
import com.ibm.engine.model.factory.KeySizeFactory;
import com.ibm.engine.model.factory.MacSizeFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.plugin.rules.detection.Memoize;
import java.util.List;
import java.util.function.Supplier;
import javax.annotation.Nonnull;
import org.sonar.plugins.java.api.tree.Tree;

public final class BcIESParameters {

    private BcIESParameters() {
        // nothing
    }

    private static final IDetectionRule<Tree> CONSTRUCTOR_IES =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    /* Using "exact types" because IESParameters is the parent of IESWithCipherParameters */
                    .forObjectExactTypes("org.bouncycastle.crypto.params.IESParameters")
                    .forConstructor()
                    .withMethodParameter(BYTE_ARRAY_TYPE)
                    .withMethodParameter(BYTE_ARRAY_TYPE)
                    .withMethodParameter("int")
                    .shouldBeDetectedAs(new MacSizeFactory<>(Size.UnitType.BIT))
                    .asChildOfParameterWithId(-1)
                    .buildForContext(new AlgorithmParameterContext())
                    .inBundle(() -> "Bc")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> CONSTRUCTOR_IES_WITH_CIPHER_PARAMETERS =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("org.bouncycastle.crypto.params.IESWithCipherParameters")
                    .forConstructor()
                    .withMethodParameter(BYTE_ARRAY_TYPE)
                    .withMethodParameter(BYTE_ARRAY_TYPE)
                    .withMethodParameter("int")
                    .shouldBeDetectedAs(new MacSizeFactory<>(Size.UnitType.BIT))
                    .withMethodParameter("int")
                    .shouldBeDetectedAs(new KeySizeFactory<>(Size.UnitType.BIT))
                    .asChildOfParameterWithId(-1)
                    .buildForContext(new AlgorithmParameterContext())
                    .inBundle(() -> "Bc")
                    .withoutDependingDetectionRules();

    private static final Supplier<List<IDetectionRule<Tree>>> RULES =
            Memoize.of(() -> List.of(CONSTRUCTOR_IES, CONSTRUCTOR_IES_WITH_CIPHER_PARAMETERS));

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return RULES.get();
    }
}
