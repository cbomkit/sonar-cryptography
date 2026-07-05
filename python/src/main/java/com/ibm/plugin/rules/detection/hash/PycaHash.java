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
package com.ibm.plugin.rules.detection.hash;

import com.ibm.engine.model.context.DigestContext;
import com.ibm.engine.model.factory.AlgorithmFactory;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.plugin.rules.detection.Memoize;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.function.Supplier;
import javax.annotation.Nonnull;
import org.sonar.plugins.python.api.tree.Tree;

@SuppressWarnings("java:S1192")
public final class PycaHash {

    private PycaHash() {
        // private
    }

    @SuppressWarnings("java:S2386")
    public static final List<String> hashes =
            Arrays.asList(
                    "SHA1",
                    "SHA512_224",
                    "SHA512_256",
                    "SHA224",
                    "SHA256",
                    "SHA384",
                    "SHA512",
                    "SHA3_224",
                    "SHA3_256",
                    "SHA3_384",
                    "SHA3_512",
                    "SHAKE128",
                    "SHAKE256",
                    "MD5",
                    "BLAKE2b",
                    "BLAKE2s",
                    "SM3");

    private static @Nonnull List<IDetectionRule<Tree>> hashesRules() {
        LinkedList<IDetectionRule<Tree>> rules = new LinkedList<>();
        for (final String hash : PycaHash.hashes) {
            rules.add(
                    new DetectionRuleBuilder<Tree>()
                            .createDetectionRule()
                            .forObjectTypes("cryptography.hazmat.primitives.hashes")
                            .forMethods(hash)
                            .shouldBeDetectedAs(new ValueActionFactory<>(hash))
                            .withAnyParameters()
                            .buildForContext(new DigestContext())
                            .inBundle(() -> "Pyca")
                            .withoutDependingDetectionRules());
        }
        return rules;
    }

    private static final IDetectionRule<Tree> PRE_HASH =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("cryptography.hazmat.primitives.asymmetric.utils")
                    .forMethods("Prehashed")
                    .withMethodParameter("cryptography.hazmat.primitives.hashes.*")
                    .addDependingDetectionRules(hashesRules())
                    .buildForContext(new DigestContext())
                    .inBundle(() -> "Pyca")
                    .withoutDependingDetectionRules();

    // Detects hashes.Hash(hashes.SHA256()) and similar direct hash-computation usages.
    private static final IDetectionRule<Tree> HASH_WRAPPER =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("cryptography.hazmat.primitives.hashes")
                    .forMethods("Hash")
                    .withMethodParameter("cryptography.hazmat.primitives.hashes.*")
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .buildForContext(new DigestContext())
                    .inBundle(() -> "Pyca")
                    .withoutDependingDetectionRules();

    private static final Supplier<List<IDetectionRule<Tree>>> RULES =
            Memoize.of(PycaHash::buildRules);

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return RULES.get();
    }

    @Nonnull
    private static List<IDetectionRule<Tree>> buildRules() {
        final List<IDetectionRule<Tree>> hashAndPrehashRules = new LinkedList<>(hashesRules());
        hashAndPrehashRules.add(PRE_HASH);
        return hashAndPrehashRules;
    }

    @Nonnull
    public static List<IDetectionRule<Tree>> wrapperRules() {
        return List.of(HASH_WRAPPER);
    }
}
