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
package com.ibm.plugin.rules.detection.bc.encapsulatedsecret;

import com.ibm.engine.model.Size;
import com.ibm.engine.model.context.KeyContext;
import com.ibm.engine.model.factory.KeySizeFactory;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.plugin.rules.detection.Memoize;
import com.ibm.plugin.rules.detection.bc.BouncyCastleInfoMap;
import com.ibm.plugin.rules.detection.bc.derivationfunction.BcDerivationFunction;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import java.util.stream.Stream;
import javax.annotation.Nonnull;
import org.sonar.plugins.java.api.tree.Tree;

public final class BcEncapsulatedSecretGenerator {

    private BcEncapsulatedSecretGenerator() {
        // nothing
    }

    private static final BouncyCastleInfoMap infoMap = new BouncyCastleInfoMap();

    static {
        infoMap.putKey("BIKEKEMGenerator").putType("org.bouncycastle.pqc.crypto.bike.");
        infoMap.putKey("CMCEKEMGenerator").putType("org.bouncycastle.pqc.crypto.cmce.");
        infoMap.putKey("FrodoKEMGenerator").putType("org.bouncycastle.pqc.crypto.frodo.");
        infoMap.putKey("HQCKEMGenerator").putType("org.bouncycastle.pqc.crypto.hqc.");
        infoMap.putKey("KyberKEMGenerator")
                .putType("org.bouncycastle.pqc.crypto.crystals.kyber."); // deprecated since bc 1.79
        infoMap.putKey("MLKEMGenerator")
                .putType("org.bouncycastle.pqc.crypto.mlkem."); // new since bc 1.79
        infoMap.putKey("NTRUKEMGenerator").putType("org.bouncycastle.pqc.crypto.ntru.");
        infoMap.putKey("NTRULPRimeKEMGenerator").putType("org.bouncycastle.pqc.crypto.ntruprime.");
        infoMap.putKey("SABERKEMGenerator").putType("org.bouncycastle.pqc.crypto.saber.");
        infoMap.putKey("SNTRUPrimeKEMGenerator").putType("org.bouncycastle.pqc.crypto.ntruprime.");
    }

    private static @Nonnull List<IDetectionRule<Tree>> simpleConstructors() {
        List<IDetectionRule<Tree>> constructorsList = new LinkedList<>();

        for (Map.Entry<String, BouncyCastleInfoMap.Info> entry : infoMap.entrySet()) {
            String generator = entry.getKey();
            String type = entry.getValue().getType();
            constructorsList.add(
                    new DetectionRuleBuilder<Tree>()
                            .createDetectionRule()
                            .forObjectTypes(type + generator)
                            .forConstructor()
                            .shouldBeDetectedAs(new ValueActionFactory<>(generator))
                            .withMethodParameter("java.security.SecureRandom")
                            .buildForContext(new KeyContext(Map.of("kind", "KEM")))
                            .inBundle(() -> "Bc")
                            .withDependingDetectionRules(BcGenerateEncapsulatedSecret.rules()));
        }
        return constructorsList;
    }

    private static @Nonnull List<IDetectionRule<Tree>> specialConstructors() {
        List<IDetectionRule<Tree>> constructorsList = new LinkedList<>();

        constructorsList.add(
                new DetectionRuleBuilder<Tree>()
                        .createDetectionRule()
                        .forObjectTypes("org.bouncycastle.crypto.kems.RSAKEMGenerator")
                        .forConstructor()
                        .shouldBeDetectedAs(new ValueActionFactory<>("RSAKEMGenerator"))
                        .withMethodParameter("int")
                        .shouldBeDetectedAs(new KeySizeFactory<>(Size.UnitType.BIT))
                        .asChildOfParameterWithId(-1)
                        .withMethodParameter("org.bouncycastle.crypto.DerivationFunction")
                        .addDependingDetectionRules(BcDerivationFunction.rules())
                        .withMethodParameter("java.security.SecureRandom")
                        .buildForContext(new KeyContext(Map.of("kind", "KEM")))
                        .inBundle(() -> "Bc")
                        .withoutDependingDetectionRules());

        constructorsList.add(
                new DetectionRuleBuilder<Tree>()
                        .createDetectionRule()
                        .forObjectTypes("org.bouncycastle.crypto.kems.ECIESKEMGenerator")
                        .forConstructor()
                        .shouldBeDetectedAs(new ValueActionFactory<>("ECIESKEMGenerator"))
                        .withMethodParameter("int")
                        .shouldBeDetectedAs(new KeySizeFactory<>(Size.UnitType.BIT))
                        .asChildOfParameterWithId(-1)
                        .withMethodParameter("org.bouncycastle.crypto.DerivationFunction")
                        .addDependingDetectionRules(BcDerivationFunction.rules())
                        .withMethodParameter("java.security.SecureRandom")
                        .buildForContext(new KeyContext(Map.of("kind", "KEM")))
                        .inBundle(() -> "Bc")
                        .withoutDependingDetectionRules());

        constructorsList.add(
                new DetectionRuleBuilder<Tree>()
                        .createDetectionRule()
                        .forObjectTypes("org.bouncycastle.crypto.kems.ECIESKEMGenerator")
                        .forConstructor()
                        .shouldBeDetectedAs(new ValueActionFactory<>("ECIESKEMGenerator"))
                        .withMethodParameter("int")
                        .shouldBeDetectedAs(new KeySizeFactory<>(Size.UnitType.BIT))
                        .asChildOfParameterWithId(-1)
                        .withMethodParameter("org.bouncycastle.crypto.DerivationFunction")
                        .addDependingDetectionRules(BcDerivationFunction.rules())
                        .withMethodParameter("java.security.SecureRandom")
                        .withMethodParameter("boolean")
                        .withMethodParameter("boolean")
                        .withMethodParameter("boolean")
                        .buildForContext(new KeyContext(Map.of("kind", "KEM")))
                        .inBundle(() -> "Bc")
                        .withoutDependingDetectionRules());

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
