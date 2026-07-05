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
package com.ibm.plugin.rules.detection.bc.mac;

import static com.ibm.plugin.rules.detection.TypeShortcuts.BYTE_ARRAY_TYPE;

import com.ibm.engine.model.Size;
import com.ibm.engine.model.context.MacContext;
import com.ibm.engine.model.factory.BlockSizeFactory;
import com.ibm.engine.model.factory.MacSizeFactory;
import com.ibm.engine.model.factory.ParameterIdentifierFactory;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.plugin.rules.detection.Memoize;
import com.ibm.plugin.rules.detection.bc.aeadcipher.BcKGCMBlockCipher;
import com.ibm.plugin.rules.detection.bc.blockcipher.BcBlockCipher;
import com.ibm.plugin.rules.detection.bc.blockcipherpadding.BcBlockCipherPadding;
import com.ibm.plugin.rules.detection.bc.digest.BcDigests;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.function.Supplier;
import java.util.stream.Stream;
import javax.annotation.Nonnull;
import org.sonar.plugins.java.api.tree.Tree;

public final class BcMac {

    private BcMac() {
        // private
    }

    private static final List<String> constructorBlockCipher =
            /*
             * List of classes implementing Mac having a constructor
             * taking a BlockCipher argument
             */
            Arrays.asList(
                    "BlockCipherMac",
                    "CBCBlockCipherMac",
                    "CFBBlockCipherMac",
                    "CMac",
                    "CMacWithIV",
                    "ISO9797Alg3Mac",
                    "Poly1305");

    private static final List<String> constructorBlockCipherAndMacSize =
            /*
             * List of classes implementing Mac having a constructor
             * taking a BlockCipher and an int macSizeBits for arguments
             */
            Arrays.asList(
                    "BlockCipherMac", "CBCBlockCipherMac", "CMac", "CMacWithIV", "ISO9797Alg3Mac");

    private static final List<String> constructorMacSize =
            /*
             * List of classes implementing Mac having a constructor
             * taking an int macSizeBits argument
             */
            Arrays.asList("DSTU7564Mac", "Zuc256Mac");

    private static final List<String> constructorBlockCipherAndBlockCipherPadding =
            /*
             * List of classes implementing Mac having a constructor
             * taking a BlockCipher and a BlockCipherPadding for arguments
             */
            Arrays.asList("CBCBlockCipherMac", "CFBBlockCipherMac", "ISO9797Alg3Mac");

    private static final List<String> constructorBlockCipherAndMacSizeAndBlockCipherPadding =
            /*
             * List of classes implementing Mac having a constructor
             * taking a BlockCipher and a BlockCipherPadding for arguments
             */
            Arrays.asList("CBCBlockCipherMac", "ISO9797Alg3Mac");

    private static final List<String> constructorDigest =
            /*
             * List of classes implementing Mac having a constructor
             * taking a Digest argument
             */
            Arrays.asList("HMac", "OldHMac");

    private static final List<String> constructorMethodDetection =
            /*
             * List of classes implementing Mac with constructor(s)
             * whose parameters do not matter (we capture all of them)
             */
            Arrays.asList(
                    "Blake3Mac",
                    "GOST28147Mac",
                    "SipHash", // parent class of `SipHash128`
                    "SipHash128",
                    "VMPCMac", // just an empty constructor
                    "Zuc128Mac" // just an empty constructor
                    );

    private static @Nonnull List<IDetectionRule<Tree>> simpleConstructors() {
        List<IDetectionRule<Tree>> constructorsList = new LinkedList<>();

        for (String macClass : constructorBlockCipher) {
            constructorsList.add(
                    new DetectionRuleBuilder<Tree>()
                            .createDetectionRule()
                            .forObjectTypes("org.bouncycastle.crypto.macs." + macClass)
                            .forConstructor()
                            .shouldBeDetectedAs(new ValueActionFactory<>(macClass))
                            .withMethodParameter("org.bouncycastle.crypto.BlockCipher")
                            .addDependingDetectionRules(BcBlockCipher.all())
                            .buildForContext(new MacContext())
                            .inBundle(() -> "Bc")
                            .withDependingDetectionRules(BcMacInit.rules()));
        }

        for (String macClass : constructorBlockCipherAndMacSize) {
            constructorsList.add(
                    new DetectionRuleBuilder<Tree>()
                            .createDetectionRule()
                            .forObjectTypes("org.bouncycastle.crypto.macs." + macClass)
                            .forConstructor()
                            .shouldBeDetectedAs(new ValueActionFactory<>(macClass))
                            .withMethodParameter("org.bouncycastle.crypto.BlockCipher")
                            .addDependingDetectionRules(BcBlockCipher.all())
                            .withMethodParameter("int")
                            .shouldBeDetectedAs(new MacSizeFactory<>(Size.UnitType.BIT))
                            .asChildOfParameterWithId(-1)
                            .buildForContext(new MacContext())
                            .inBundle(() -> "Bc")
                            .withDependingDetectionRules(BcMacInit.rules()));
        }

        for (String macClass : constructorMacSize) {
            constructorsList.add(
                    new DetectionRuleBuilder<Tree>()
                            .createDetectionRule()
                            .forObjectTypes("org.bouncycastle.crypto.macs." + macClass)
                            .forConstructor()
                            .shouldBeDetectedAs(new ValueActionFactory<>(macClass))
                            .withMethodParameter("int")
                            .shouldBeDetectedAs(new MacSizeFactory<>(Size.UnitType.BIT))
                            .asChildOfParameterWithId(-1)
                            .buildForContext(new MacContext())
                            .inBundle(() -> "Bc")
                            .withDependingDetectionRules(BcMacInit.rules()));
        }

        for (String macClass : constructorBlockCipherAndBlockCipherPadding) {
            constructorsList.add(
                    new DetectionRuleBuilder<Tree>()
                            .createDetectionRule()
                            .forObjectTypes("org.bouncycastle.crypto.macs." + macClass)
                            .forConstructor()
                            .shouldBeDetectedAs(new ValueActionFactory<>(macClass))
                            .withMethodParameter("org.bouncycastle.crypto.BlockCipher")
                            .addDependingDetectionRules(BcBlockCipher.all())
                            .withMethodParameter(
                                    "org.bouncycastle.crypto.paddings.BlockCipherPadding")
                            .addDependingDetectionRules(BcBlockCipherPadding.rules())
                            .buildForContext(new MacContext())
                            .inBundle(() -> "Bc")
                            .withDependingDetectionRules(BcMacInit.rules()));
        }

        for (String macClass : constructorBlockCipherAndMacSizeAndBlockCipherPadding) {
            constructorsList.add(
                    new DetectionRuleBuilder<Tree>()
                            .createDetectionRule()
                            .forObjectTypes("org.bouncycastle.crypto.macs." + macClass)
                            .forConstructor()
                            .shouldBeDetectedAs(new ValueActionFactory<>(macClass))
                            .withMethodParameter("org.bouncycastle.crypto.BlockCipher")
                            .addDependingDetectionRules(BcBlockCipher.all())
                            .withMethodParameter("int")
                            .shouldBeDetectedAs(new MacSizeFactory<>(Size.UnitType.BIT))
                            .asChildOfParameterWithId(-1)
                            .withMethodParameter(
                                    "org.bouncycastle.crypto.paddings.BlockCipherPadding")
                            .addDependingDetectionRules(BcBlockCipherPadding.rules())
                            .buildForContext(new MacContext())
                            .inBundle(() -> "Bc")
                            .withDependingDetectionRules(BcMacInit.rules()));
        }

        for (String macClass : constructorDigest) {
            constructorsList.add(
                    new DetectionRuleBuilder<Tree>()
                            .createDetectionRule()
                            .forObjectTypes("org.bouncycastle.crypto.macs." + macClass)
                            .forConstructor()
                            .shouldBeDetectedAs(new ValueActionFactory<>(macClass))
                            .withMethodParameter("org.bouncycastle.crypto.Digest")
                            .addDependingDetectionRules(BcDigests.rules())
                            .buildForContext(new MacContext())
                            .inBundle(() -> "Bc")
                            .withDependingDetectionRules(BcMacInit.rules()));
        }

        for (String macClass : constructorMethodDetection) {
            constructorsList.add(
                    new DetectionRuleBuilder<Tree>()
                            .createDetectionRule()
                            // Using "exact types" because SipHash is the parent of SipHash128
                            .forObjectExactTypes("org.bouncycastle.crypto.macs." + macClass)
                            .forConstructor()
                            .shouldBeDetectedAs(new ValueActionFactory<>(macClass))
                            // We want to capture all possible constructors (some have arguments)
                            .withAnyParameters()
                            .buildForContext(new MacContext())
                            .inBundle(() -> "Bc")
                            .withDependingDetectionRules(BcMacInit.rules()));
        }
        return constructorsList;
    }

    private static @Nonnull List<IDetectionRule<Tree>> specialConstructors() {
        List<IDetectionRule<Tree>> constructorsList = new LinkedList<>();

        constructorsList.add(
                new DetectionRuleBuilder<Tree>()
                        .createDetectionRule()
                        .forObjectTypes("org.bouncycastle.crypto.macs.GMac")
                        .forConstructor()
                        .shouldBeDetectedAs(new ValueActionFactory<>("GMac"))
                        .withMethodParameter("org.bouncycastle.crypto.modes.GCMModeCipher")
                        .addDependingDetectionRules(BcBlockCipher.all())
                        .buildForContext(new MacContext())
                        .inBundle(() -> "Bc")
                        .withDependingDetectionRules(BcMacInit.rules()));

        constructorsList.add(
                new DetectionRuleBuilder<Tree>()
                        .createDetectionRule()
                        .forObjectTypes("org.bouncycastle.crypto.macs.GMac")
                        .forConstructor()
                        .shouldBeDetectedAs(new ValueActionFactory<>("GMac"))
                        .withMethodParameter("org.bouncycastle.crypto.modes.GCMModeCipher")
                        .addDependingDetectionRules(BcBlockCipher.all())
                        .withMethodParameter("int")
                        .shouldBeDetectedAs(new MacSizeFactory<>(Size.UnitType.BIT))
                        .asChildOfParameterWithId(-1)
                        .buildForContext(new MacContext())
                        .inBundle(() -> "Bc")
                        .withDependingDetectionRules(BcMacInit.rules()));

        constructorsList.add(
                new DetectionRuleBuilder<Tree>()
                        .createDetectionRule()
                        .forObjectTypes("org.bouncycastle.crypto.macs.KGMac")
                        .forConstructor()
                        .shouldBeDetectedAs(new ValueActionFactory<>("KGMac"))
                        .withMethodParameter("org.bouncycastle.crypto.modes.KGCMBlockCipher")
                        .addDependingDetectionRules(BcKGCMBlockCipher.rules())
                        .buildForContext(new MacContext())
                        .inBundle(() -> "Bc")
                        .withDependingDetectionRules(BcMacInit.rules()));

        constructorsList.add(
                new DetectionRuleBuilder<Tree>()
                        .createDetectionRule()
                        .forObjectTypes("org.bouncycastle.crypto.macs.KGMac")
                        .forConstructor()
                        .shouldBeDetectedAs(new ValueActionFactory<>("KGMac"))
                        .withMethodParameter("org.bouncycastle.crypto.modes.KGCMBlockCipher")
                        .addDependingDetectionRules(BcKGCMBlockCipher.rules())
                        .withMethodParameter("int")
                        .shouldBeDetectedAs(new MacSizeFactory<>(Size.UnitType.BIT))
                        .asChildOfParameterWithId(-1)
                        .buildForContext(new MacContext())
                        .inBundle(() -> "Bc")
                        .withDependingDetectionRules(BcMacInit.rules()));

        constructorsList.add(
                new DetectionRuleBuilder<Tree>()
                        .createDetectionRule()
                        .forObjectTypes("org.bouncycastle.crypto.macs.Poly1305")
                        .forConstructor()
                        .shouldBeDetectedAs(new ValueActionFactory<>("Poly1305"))
                        .withoutParameters()
                        .buildForContext(new MacContext())
                        .inBundle(() -> "Bc")
                        .withDependingDetectionRules(BcMacInit.rules()));

        constructorsList.add(
                new DetectionRuleBuilder<Tree>()
                        .createDetectionRule()
                        .forObjectTypes("org.bouncycastle.crypto.macs.CFBBlockCipherMac")
                        .forConstructor()
                        .shouldBeDetectedAs(new ValueActionFactory<>("CFBBlockCipherMac"))
                        .withMethodParameter("org.bouncycastle.crypto.BlockCipher")
                        .addDependingDetectionRules(BcBlockCipher.all())
                        .withMethodParameter("int")
                        .shouldBeDetectedAs(new BlockSizeFactory<>(Size.UnitType.BIT))
                        .asChildOfParameterWithId(-1)
                        .withMethodParameter("int")
                        .shouldBeDetectedAs(new MacSizeFactory<>(Size.UnitType.BIT))
                        .asChildOfParameterWithId(-1)
                        .buildForContext(new MacContext())
                        .inBundle(() -> "Bc")
                        .withDependingDetectionRules(BcMacInit.rules()));

        constructorsList.add(
                new DetectionRuleBuilder<Tree>()
                        .createDetectionRule()
                        .forObjectTypes("org.bouncycastle.crypto.macs.CFBBlockCipherMac")
                        .forConstructor()
                        .shouldBeDetectedAs(new ValueActionFactory<>("CFBBlockCipherMac"))
                        .withMethodParameter("org.bouncycastle.crypto.BlockCipher")
                        .addDependingDetectionRules(BcBlockCipher.all())
                        .withMethodParameter("int")
                        .shouldBeDetectedAs(new BlockSizeFactory<>(Size.UnitType.BIT))
                        .asChildOfParameterWithId(-1)
                        .withMethodParameter("int")
                        .shouldBeDetectedAs(new MacSizeFactory<>(Size.UnitType.BIT))
                        .asChildOfParameterWithId(-1)
                        .withMethodParameter("org.bouncycastle.crypto.paddings.BlockCipherPadding")
                        .addDependingDetectionRules(BcBlockCipherPadding.rules())
                        .buildForContext(new MacContext())
                        .inBundle(() -> "Bc")
                        .withDependingDetectionRules(BcMacInit.rules()));

        constructorsList.add(
                new DetectionRuleBuilder<Tree>()
                        .createDetectionRule()
                        .forObjectTypes("org.bouncycastle.crypto.macs.DSTU7624Mac")
                        .forConstructor()
                        .shouldBeDetectedAs(new ValueActionFactory<>("DSTU7624Mac"))
                        .withMethodParameter("int")
                        .shouldBeDetectedAs(new MacSizeFactory<>(Size.UnitType.BIT))
                        .asChildOfParameterWithId(-1)
                        .withMethodParameter("int")
                        .buildForContext(new MacContext())
                        .inBundle(() -> "Bc")
                        .withDependingDetectionRules(BcMacInit.rules()));

        constructorsList.add(
                new DetectionRuleBuilder<Tree>()
                        .createDetectionRule()
                        .forObjectTypes("org.bouncycastle.crypto.macs.KMAC")
                        .forConstructor()
                        .shouldBeDetectedAs(new ValueActionFactory<>("KMAC"))
                        .withMethodParameter("int")
                        .shouldBeDetectedAs(new ParameterIdentifierFactory<>())
                        .asChildOfParameterWithId(-1)
                        .withMethodParameter(BYTE_ARRAY_TYPE)
                        .buildForContext(new MacContext())
                        .inBundle(() -> "Bc")
                        .withDependingDetectionRules(BcMacInit.rules()));

        constructorsList.add(
                new DetectionRuleBuilder<Tree>()
                        .createDetectionRule()
                        .forObjectTypes("org.bouncycastle.crypto.macs.SkeinMac")
                        .forConstructor()
                        .shouldBeDetectedAs(new ValueActionFactory<>("SkeinMac"))
                        .withMethodParameter("int")
                        .shouldBeDetectedAs(new BlockSizeFactory<>(Size.UnitType.BIT))
                        .asChildOfParameterWithId(-1)
                        .withMethodParameter("int")
                        .shouldBeDetectedAs(new MacSizeFactory<>(Size.UnitType.BIT))
                        .asChildOfParameterWithId(-1)
                        .buildForContext(new MacContext())
                        .inBundle(() -> "Bc")
                        .withDependingDetectionRules(BcMacInit.rules()));

        constructorsList.add(
                new DetectionRuleBuilder<Tree>()
                        .createDetectionRule()
                        .forObjectTypes("org.bouncycastle.crypto.macs.SkeinMac")
                        .forConstructor()
                        .shouldBeDetectedAs(new ValueActionFactory<>("SkeinMac"))
                        .withMethodParameter("org.bouncycastle.crypto.macs.SkeinMac")
                        .buildForContext(new MacContext())
                        .inBundle(() -> "Bc")
                        .withDependingDetectionRules(BcMacInit.rules()));

        return constructorsList;
    }

    private static final Supplier<List<IDetectionRule<Tree>>> RULES =
            Memoize.of(
                    () ->
                            Stream.of(simpleConstructors().stream(), specialConstructors().stream())
                                    .flatMap(i -> i)
                                    .toList());

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return RULES.get();
    }
}
