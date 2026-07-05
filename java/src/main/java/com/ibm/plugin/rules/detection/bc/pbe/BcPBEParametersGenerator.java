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
package com.ibm.plugin.rules.detection.bc.pbe;

import com.ibm.engine.model.context.CipherContext;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.plugin.rules.detection.Memoize;
import com.ibm.plugin.rules.detection.bc.digest.BcDigests;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import javax.annotation.Nonnull;
import org.sonar.plugins.java.api.tree.Tree;

public final class BcPBEParametersGenerator {

    private BcPBEParametersGenerator() {
        // private
    }

    private static final List<String> constructorDigest =
            /*
             * List of children classes of PBEParametersGenerator having a
             * constructor taking a Digest argument
             */
            Arrays.asList(
                    "OpenSSLPBEParametersGenerator",
                    "PKCS12ParametersGenerator",
                    "PKCS5S1ParametersGenerator",
                    "PKCS5S2ParametersGenerator");

    private static @Nonnull List<IDetectionRule<Tree>> simpleConstructors() {
        List<IDetectionRule<Tree>> constructorsList = new LinkedList<>();

        /* Constructor without argument */
        constructorsList.add(
                new DetectionRuleBuilder<Tree>()
                        .createDetectionRule()
                        .forObjectTypes(
                                "org.bouncycastle.crypto.generators."
                                        + "PKCS5S2ParametersGenerator")
                        .forConstructor()
                        .shouldBeDetectedAs(new ValueActionFactory<>("PKCS5S2ParametersGenerator"))
                        .withoutParameters()
                        .buildForContext(new CipherContext(Map.of("kind", "PBE")))
                        .inBundle(() -> "Bc")
                        .withoutDependingDetectionRules());

        /*
         * With this constructor of `OpenSSLPBEParametersGenerator`, no `Digest` argument is provided:
         * it uses the default MD5 which we represent (for the translation) by capturing
         * the value `ChaCha20Poly1305[MD5]`
         */
        constructorsList.add(
                new DetectionRuleBuilder<Tree>()
                        .createDetectionRule()
                        .forObjectTypes(
                                "org.bouncycastle.crypto.generators."
                                        + "OpenSSLPBEParametersGenerator")
                        .forConstructor()
                        .shouldBeDetectedAs(
                                new ValueActionFactory<>("OpenSSLPBEParametersGenerator[MD5]"))
                        .withoutParameters()
                        .buildForContext(new CipherContext(Map.of("kind", "PBE")))
                        .inBundle(() -> "Bc")
                        .withoutDependingDetectionRules());

        /* All constructors with a Digest argument */
        for (String pbeClass : constructorDigest) {
            constructorsList.add(
                    new DetectionRuleBuilder<Tree>()
                            .createDetectionRule()
                            .forObjectTypes("org.bouncycastle.crypto.generators." + pbeClass)
                            .forConstructor()
                            .shouldBeDetectedAs(new ValueActionFactory<>(pbeClass))
                            .withMethodParameter("org.bouncycastle.crypto.Digest")
                            .addDependingDetectionRules(BcDigests.rules())
                            .buildForContext(new CipherContext(Map.of("kind", "PBE")))
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
