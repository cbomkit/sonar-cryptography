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
package com.ibm.plugin.rules.detection.bc.blockcipher;

import com.ibm.engine.model.Size;
import com.ibm.engine.model.context.CipherContext;
import com.ibm.engine.model.context.IDetectionContext;
import com.ibm.engine.model.factory.BlockSizeFactory;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.plugin.rules.detection.Memoize;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.sonar.plugins.java.api.tree.Tree;

public final class BcBlockCipherEngine {

    private BcBlockCipherEngine() {
        // nothing
    }

    public static final List<String> enginesEmptyConstructors =
            List.of(
                    "AESEngine",
                    "AESFastEngine",
                    "AESLightEngine",
                    "ARIAEngine",
                    "BlowfishEngine",
                    "CamelliaEngine",
                    "CamelliaLightEngine",
                    "CAST5Engine",
                    "CAST6Engine",
                    "DESedeEngine",
                    "DESEngine",
                    "GOST28147Engine",
                    "GOST3412_2015Engine",
                    "IDEAEngine",
                    "LEAEngine",
                    "NoekeonEngine",
                    "NullEngine",
                    "RC2Engine",
                    "RC532Engine",
                    "RC564Engine",
                    "RC6Engine",
                    "RijndaelEngine",
                    "SEEDEngine",
                    "SerpentEngine",
                    "Shacal2Engine",
                    "SkipjackEngine",
                    "SM4Engine",
                    "TEAEngine",
                    "TnepresEngine",
                    "TwofishEngine",
                    "XTEAEngine");

    public static final List<String> enginesBlockSizeConstructors =
            List.of("DSTU7624Engine", "NullEngine", "RijndaelEngine", "ThreefishEngine");

    private static final List<IDetectionRule<Tree>> simpleConstructors(
            @Nullable IDetectionContext detectionValueContext) {
        List<IDetectionRule<Tree>> constructorsList = new LinkedList<>();
        IDetectionContext context =
                detectionValueContext != null
                        ? detectionValueContext
                        : new CipherContext(Map.of("kind", "BLOCK_CIPHER_ENGINE"));

        // Simple empty constructors
        for (String engine : enginesEmptyConstructors) {
            constructorsList.add(
                    new DetectionRuleBuilder<Tree>()
                            .createDetectionRule()
                            .forObjectTypes("org.bouncycastle.crypto.engines." + engine)
                            .forConstructor()
                            .shouldBeDetectedAs(new ValueActionFactory<>(engine))
                            .withoutParameters()
                            .buildForContext(context)
                            .inBundle(() -> "Bc")
                            .withDependingDetectionRules(BcBlockCipherInit.rules()));
        }

        // Constructors with the block size
        for (String engine : enginesBlockSizeConstructors) {
            constructorsList.add(
                    new DetectionRuleBuilder<Tree>()
                            .createDetectionRule()
                            .forObjectTypes("org.bouncycastle.crypto.engines." + engine)
                            .forConstructor()
                            .shouldBeDetectedAs(new ValueActionFactory<>(engine))
                            .withMethodParameter("int")
                            .shouldBeDetectedAs(new BlockSizeFactory<>(Size.UnitType.BIT))
                            .asChildOfParameterWithId(-1)
                            .buildForContext(context)
                            .inBundle(() -> "Bc")
                            .withDependingDetectionRules(BcBlockCipherInit.rules()));
        }

        // `newInstance` for AESEngine
        String engine = "AESEngine";
        constructorsList.add(
                new DetectionRuleBuilder<Tree>()
                        .createDetectionRule()
                        .forObjectTypes("org.bouncycastle.crypto.engines." + engine)
                        .forMethods("newInstance")
                        .shouldBeDetectedAs(new ValueActionFactory<>(engine))
                        .withoutParameters()
                        .buildForContext(context)
                        .inBundle(() -> "Bc")
                        .withDependingDetectionRules(BcBlockCipherInit.rules()));

        return constructorsList;
    }

    private static final Supplier<List<IDetectionRule<Tree>>> RULES =
            Memoize.of(() -> simpleConstructors(null));

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return RULES.get();
    }

    @Nonnull
    public static List<IDetectionRule<Tree>> rules(
            @Nullable IDetectionContext detectionValueContext) {
        return detectionValueContext == null
                ? RULES.get()
                : simpleConstructors(detectionValueContext);
    }
}
