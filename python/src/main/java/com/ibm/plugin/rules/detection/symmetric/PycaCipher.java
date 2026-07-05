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
package com.ibm.plugin.rules.detection.symmetric;

import com.ibm.engine.model.CipherAction;
import com.ibm.engine.model.context.CipherContext;
import com.ibm.engine.model.factory.AlgorithmFactory;
import com.ibm.engine.model.factory.CipherActionFactory;
import com.ibm.engine.model.factory.ModeFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.plugin.rules.detection.Memoize;
import com.ibm.plugin.rules.detection.padding.PycaPadding;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.function.Supplier;
import javax.annotation.Nonnull;
import org.sonar.plugins.python.api.tree.Tree;

@SuppressWarnings({"java:S2386", "java:S1192"})
public final class PycaCipher {

    private PycaCipher() {
        // private
    }

    public static final List<String> blockCiphers =
            Arrays.asList(
                    "AES",
                    "AES128",
                    "AES256",
                    "Camellia",
                    "TripleDES",
                    "CAST5",
                    "SEED",
                    "SM4",
                    "Blowfish",
                    "IDEA");
    public static final List<String> streamCiphers = Arrays.asList("ChaCha20", "ARC4");

    public static final List<String> modes =
            Arrays.asList("CBC", "CTR", "OFB", "CFB", "CFB8", "GCM", "XTS", "ECB");

    private static final IDetectionRule<Tree> ENCRYPT_CIPHER =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("cryptography.hazmat.primitives.ciphers.Cipher")
                    .forMethods("encryptor")
                    .shouldBeDetectedAs(new CipherActionFactory<>(CipherAction.Action.ENCRYPT))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "Pyca")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> DECRYPT_CIPHER =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("cryptography.hazmat.primitives.ciphers.Cipher")
                    .forMethods("decryptor")
                    .shouldBeDetectedAs(new CipherActionFactory<>(CipherAction.Action.DECRYPT))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "Pyca")
                    .withoutDependingDetectionRules();

    private static @Nonnull List<IDetectionRule<Tree>> followingNewCipherRules() {
        final List<IDetectionRule<Tree>> encryptionRules =
                new LinkedList<>(List.of(DECRYPT_CIPHER, ENCRYPT_CIPHER));
        encryptionRules.addAll(PycaPadding.rules());
        return encryptionRules;
    }

    private static final IDetectionRule<Tree> NEW_CIPHER =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("cryptography.hazmat.primitives.ciphers")
                    .forMethods("Cipher")
                    .withMethodParameter("cryptography.hazmat.primitives.ciphers.algorithms.*")
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .addDependingDetectionRules(followingNewCipherRules())
                    .withMethodParameter("cryptography.hazmat.primitives.ciphers.modes.*")
                    .shouldBeDetectedAs(new ModeFactory<>())
                    .asChildOfParameterWithId(0)
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "Pyca")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> STREAM_CIPHER =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("cryptography.hazmat.primitives.ciphers")
                    .forMethods("Cipher")
                    .withMethodParameter("cryptography.hazmat.primitives.ciphers.algorithms.*")
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .addDependingDetectionRules(followingNewCipherRules())
                    .withMethodParameter("None")
                    .shouldBeDetectedAs(new ModeFactory<>())
                    .asChildOfParameterWithId(0)
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "Pyca")
                    .withoutDependingDetectionRules();

    private static final Supplier<List<IDetectionRule<Tree>>> RULES =
            Memoize.of(PycaCipher::buildRules);

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return RULES.get();
    }

    @Nonnull
    private static List<IDetectionRule<Tree>> buildRules() {
        return List.of(NEW_CIPHER, STREAM_CIPHER);
    }
}
