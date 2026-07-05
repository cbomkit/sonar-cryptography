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
package com.ibm.plugin.rules.detection.bc.blockcipherpadding;

import com.ibm.engine.model.context.CipherContext;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.plugin.rules.detection.Memoize;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import javax.annotation.Nonnull;
import org.sonar.plugins.java.api.tree.Tree;

public final class BcBlockCipherPadding {
    private BcBlockCipherPadding() {
        // nothing
    }

    public static final List<String> paddings =
            List.of(
                    "ISO10126d2Padding",
                    "ISO7816d4Padding",
                    "PKCS7Padding",
                    "TBCPadding",
                    "X923Padding",
                    "ZeroBytePadding");

    private static @Nonnull List<IDetectionRule<Tree>> simpleConstructors() {
        List<IDetectionRule<Tree>> constructorsList = new LinkedList<>();

        for (String padding : paddings) {
            constructorsList.add(
                    new DetectionRuleBuilder<Tree>()
                            .createDetectionRule()
                            .forObjectTypes("org.bouncycastle.crypto.paddings." + padding)
                            .forConstructor()
                            .shouldBeDetectedAs(new ValueActionFactory<>(padding))
                            .withoutParameters()
                            .buildForContext(new CipherContext(Map.of("kind", "PADDING")))
                            .inBundle(() -> "Bc")
                            .withoutDependingDetectionRules());
        }
        return constructorsList;
    }

    private static final Supplier<List<IDetectionRule<Tree>>> RULES =
            Memoize.of(() -> simpleConstructors());

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return RULES.get();
    }
}
