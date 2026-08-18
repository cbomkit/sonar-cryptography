/*
 * Sonar Cryptography Plugin
 * Copyright (C) 2026 PQCA
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

import com.ibm.engine.model.context.DigestContext;
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
public final class PythonCryptoHash {

    private PythonCryptoHash() {
        // private
    }

    public static final List<String> hashes =
            Arrays.asList(
                    "MD2",
                    "MD4",
                    "MD5",
                    "SHA1",
                    "SHA224",
                    "SHA256",
                    "SHA384",
                    "SHA512",
                    "SHA3_224",
                    "SHA3_256",
                    "SHA3_384",
                    "SHA3_512",
                    "RIPEMD160",
                    "keccak",
                    "TupleHash128",
                    "TupleHash256",
                    "SHAKE128",
                    "SHAKE256",
                    "cSHAKE128",
                    "cSHAKE256",
                    "KangarooTwelve",
                    "BLAKE2b",
                    "BLAKE2s");

    @Nonnull
    private static final Supplier<List<IDetectionRule<Tree>>> RULES =
            Memoize.of(PythonCryptoHash::buildRules);

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return RULES.get();
    }

    @Nonnull
    private static List<IDetectionRule<Tree>> buildRules() {
        LinkedList<IDetectionRule<Tree>> rules = new LinkedList<>();
        for (final String hash : PythonCryptoHash.hashes) {
            rules.add(
                    new DetectionRuleBuilder<Tree>()
                            .createDetectionRule()
                            .forObjectTypes("Crypto.Hash." + hash, "Cryptodome.Hash." + hash)
                            .forMethods("new")
                            .shouldBeDetectedAs(new ValueActionFactory<>(hash))
                            .withAnyParameters()
                            .buildForContext(new DigestContext())
                            .inBundle(() -> "PyCrypto")
                            .withoutDependingDetectionRules());
        }
        return rules;
    }
}
