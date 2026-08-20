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
import com.ibm.engine.rule.ContextualDetectionRuleSet;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.RuleSets;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.sonar.plugins.java.api.tree.Tree;

public final class BcBlockCipher extends ContextualDetectionRuleSet<Tree> {

    public static final List<String> blockCiphers =
            List.of(
                    "CBCBlockCipher",
                    "G3413CBCBlockCipher",
                    "G3413CFBBlockCipher",
                    "G3413CTRBlockCipher",
                    "G3413OFBBlockCipher",
                    "GCFBBlockCipher",
                    "GOFBBlockCipher",
                    "KCTRBlockCipher",
                    "OpenPGPCFBBlockCipher",
                    "SICBlockCipher");

    private static final List<IDetectionRule<Tree>> simpleConstructors(
            @Nullable IDetectionContext detectionValueContext) {
        List<IDetectionRule<Tree>> constructorsList = new LinkedList<>();
        IDetectionContext context =
                detectionValueContext != null
                        ? detectionValueContext
                        : new CipherContext(Map.of("kind", "BLOCK_CIPHER"));

        for (String blockCipher : blockCiphers) {
            constructorsList.add(
                    new DetectionRuleBuilder<Tree>()
                            .createDetectionRule()
                            .forObjectTypes("org.bouncycastle.crypto.modes." + blockCipher)
                            .forConstructor()
                            .shouldBeDetectedAs(new ValueActionFactory<>(blockCipher))
                            .withMethodParameter("org.bouncycastle.crypto.BlockCipher")
                            .addDependingDetectionRules(BcBlockCipherEngine.rules())
                            .buildForContext(context)
                            .inBundle(() -> "Bc")
                            .withDependingDetectionRules(BcBlockCipherInit.rules()));
        }
        return constructorsList;
    }

    private static final List<IDetectionRule<Tree>> specialConstructors(
            @Nullable IDetectionContext detectionValueContext) {
        List<IDetectionRule<Tree>> constructorsList = new LinkedList<>();
        IDetectionContext context =
                detectionValueContext != null
                        ? detectionValueContext
                        : new CipherContext(Map.of("kind", "BLOCK_CIPHER"));

        constructorsList.add(
                new DetectionRuleBuilder<Tree>()
                        .createDetectionRule()
                        .forObjectTypes("org.bouncycastle.crypto.modes.CBCBlockCipher")
                        .forMethods("newInstance")
                        .shouldBeDetectedAs(new ValueActionFactory<>("CBCBlockCipher"))
                        .withMethodParameter("org.bouncycastle.crypto.BlockCipher")
                        .addDependingDetectionRules(BcBlockCipherEngine.rules())
                        .buildForContext(context)
                        .inBundle(() -> "Bc")
                        .withDependingDetectionRules(BcBlockCipherInit.rules()));

        constructorsList.add(
                new DetectionRuleBuilder<Tree>()
                        .createDetectionRule()
                        .forObjectTypes("org.bouncycastle.crypto.modes.SICBlockCipher")
                        .forMethods("newInstance")
                        .shouldBeDetectedAs(new ValueActionFactory<>("SICBlockCipher"))
                        .withMethodParameter("org.bouncycastle.crypto.BlockCipher")
                        .addDependingDetectionRules(BcBlockCipherEngine.rules())
                        .buildForContext(context)
                        .inBundle(() -> "Bc")
                        .withDependingDetectionRules(BcBlockCipherInit.rules()));

        constructorsList.add(
                new DetectionRuleBuilder<Tree>()
                        .createDetectionRule()
                        .forObjectTypes("org.bouncycastle.crypto.modes.CFBBlockCipher")
                        .forConstructor()
                        .shouldBeDetectedAs(new ValueActionFactory<>("CFBBlockCipher"))
                        .withMethodParameter("org.bouncycastle.crypto.BlockCipher")
                        .addDependingDetectionRules(BcBlockCipherEngine.rules())
                        .withMethodParameter("int")
                        .shouldBeDetectedAs(new BlockSizeFactory<>(Size.UnitType.BIT))
                        .asChildOfParameterWithId(-1)
                        .buildForContext(context)
                        .inBundle(() -> "Bc")
                        .withDependingDetectionRules(BcBlockCipherInit.rules()));

        constructorsList.add(
                new DetectionRuleBuilder<Tree>()
                        .createDetectionRule()
                        .forObjectTypes("org.bouncycastle.crypto.modes.CFBBlockCipher")
                        .forMethods("newInstance")
                        .shouldBeDetectedAs(new ValueActionFactory<>("CFBBlockCipher"))
                        .withMethodParameter("org.bouncycastle.crypto.BlockCipher")
                        .addDependingDetectionRules(BcBlockCipherEngine.rules())
                        .withMethodParameter("int")
                        .shouldBeDetectedAs(new BlockSizeFactory<>(Size.UnitType.BIT))
                        .asChildOfParameterWithId(-1)
                        .buildForContext(context)
                        .inBundle(() -> "Bc")
                        .withDependingDetectionRules(BcBlockCipherInit.rules()));

        constructorsList.add(
                new DetectionRuleBuilder<Tree>()
                        .createDetectionRule()
                        .forObjectTypes("org.bouncycastle.crypto.modes.G3413CFBBlockCipher")
                        .forConstructor()
                        .shouldBeDetectedAs(new ValueActionFactory<>("G3413CFBBlockCipher"))
                        .withMethodParameter("org.bouncycastle.crypto.BlockCipher")
                        .addDependingDetectionRules(BcBlockCipherEngine.rules())
                        .withMethodParameter("int")
                        .shouldBeDetectedAs(new BlockSizeFactory<>(Size.UnitType.BIT))
                        .asChildOfParameterWithId(-1)
                        .buildForContext(context)
                        .inBundle(() -> "Bc")
                        .withDependingDetectionRules(BcBlockCipherInit.rules()));

        constructorsList.add(
                new DetectionRuleBuilder<Tree>()
                        .createDetectionRule()
                        .forObjectTypes("org.bouncycastle.crypto.modes.G3413CTRBlockCipher")
                        .forConstructor()
                        .shouldBeDetectedAs(new ValueActionFactory<>("G3413CTRBlockCipher"))
                        .withMethodParameter("org.bouncycastle.crypto.BlockCipher")
                        .addDependingDetectionRules(BcBlockCipherEngine.rules())
                        .withMethodParameter("int")
                        .shouldBeDetectedAs(new BlockSizeFactory<>(Size.UnitType.BIT))
                        .asChildOfParameterWithId(-1)
                        .buildForContext(context)
                        .inBundle(() -> "Bc")
                        .withDependingDetectionRules(BcBlockCipherInit.rules()));

        constructorsList.add(
                new DetectionRuleBuilder<Tree>()
                        .createDetectionRule()
                        .forObjectTypes("org.bouncycastle.crypto.modes.OFBBlockCipher")
                        .forConstructor()
                        .shouldBeDetectedAs(new ValueActionFactory<>("OFBBlockCipher"))
                        .withMethodParameter("org.bouncycastle.crypto.BlockCipher")
                        .addDependingDetectionRules(BcBlockCipherEngine.rules())
                        .withMethodParameter("int")
                        .shouldBeDetectedAs(new BlockSizeFactory<>(Size.UnitType.BIT))
                        .asChildOfParameterWithId(-1)
                        .buildForContext(context)
                        .inBundle(() -> "Bc")
                        .withDependingDetectionRules(BcBlockCipherInit.rules()));

        constructorsList.add(
                new DetectionRuleBuilder<Tree>()
                        .createDetectionRule()
                        .forObjectExactTypes("org.bouncycastle.crypto.modes.PGPCFBBlockCipher")
                        .forConstructor()
                        .shouldBeDetectedAs(new ValueActionFactory<>("PGPCFBBlockCipher"))
                        .withMethodParameter("org.bouncycastle.crypto.BlockCipher")
                        .addDependingDetectionRules(BcBlockCipherEngine.rules())
                        .withMethodParameter("boolean")
                        .buildForContext(context)
                        .inBundle(() -> "Bc")
                        .withDependingDetectionRules(BcBlockCipherInit.rules()));

        return constructorsList;
    }

    @Nonnull
    @Override
    protected List<IDetectionRule<Tree>> buildRules(@Nonnull List<IDetectionContext> contexts) {
        IDetectionContext context = contextAt(contexts, 0);
        return Stream.of(
                        simpleConstructors(context).stream(), specialConstructors(context).stream())
                .flatMap(i -> i)
                .toList();
    }

    /** Temporary shim, removed in the call-site cleanup. */
    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return RuleSets.rulesOf(BcBlockCipher.class);
    }

    /** Temporary shim, removed in the call-site cleanup. */
    @Nonnull
    public static List<IDetectionRule<Tree>> rules(@Nullable IDetectionContext context) {
        return RuleSets.rulesOf(BcBlockCipher.class, context);
    }

    /** Temporary shim, removed in the call-site cleanup. */
    @Nonnull
    public static List<IDetectionRule<Tree>> all() {
        return RuleSets.rulesOf(BcBlockCipherAndEngines.class);
    }

    /** Temporary shim, removed in the call-site cleanup. */
    @Nonnull
    public static List<IDetectionRule<Tree>> all(@Nullable IDetectionContext context) {
        return RuleSets.rulesOf(BcBlockCipherAndEngines.class, context);
    }
}
