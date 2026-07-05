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
package com.ibm.plugin.rules.detection.bc.bufferedblockcipher;

import com.ibm.engine.model.context.CipherContext;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.plugin.rules.detection.Memoize;
import com.ibm.plugin.rules.detection.bc.BouncyCastleInfoMap;
import com.ibm.plugin.rules.detection.bc.blockcipher.BcBlockCipher;
import com.ibm.plugin.rules.detection.bc.blockcipherpadding.BcBlockCipherPadding;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import java.util.stream.Stream;
import javax.annotation.Nonnull;
import org.sonar.plugins.java.api.tree.Tree;

public final class BcBufferedBlockCipher {

    private BcBufferedBlockCipher() {
        // nothing
    }

    private static BouncyCastleInfoMap infoMap = new BouncyCastleInfoMap();

    static {
        String typePrefix = "org.bouncycastle.crypto.";
        infoMap.putKey("BufferedBlockCipher").putType(typePrefix); // <–– parent class
        infoMap.putKey("DefaultBufferedBlockCipher").putType(typePrefix); // <–– parent class
        infoMap.putKey("CTSBlockCipher").putType(typePrefix + "modes.");
        infoMap.putKey("KXTSBlockCipher").putType(typePrefix + "modes.");
        infoMap.putKey("OldCTSBlockCipher").putType(typePrefix + "modes.");
        infoMap.putKey("PaddedBlockCipher").putType(typePrefix + "modes.");
    }

    private static @Nonnull List<IDetectionRule<Tree>> simpleConstructors() {
        List<IDetectionRule<Tree>> constructorsList = new LinkedList<>();
        for (Map.Entry<String, BouncyCastleInfoMap.Info> entry : infoMap.entrySet()) {
            String blockCipher = entry.getKey();
            String type = entry.getValue().getType();
            constructorsList.add(
                    new DetectionRuleBuilder<Tree>()
                            .createDetectionRule()
                            .forObjectExactTypes(type + blockCipher)
                            .forConstructor()
                            .shouldBeDetectedAs(new ValueActionFactory<>(blockCipher))
                            .withMethodParameter("org.bouncycastle.crypto.BlockCipher")
                            .addDependingDetectionRules(BcBlockCipher.all())
                            .buildForContext(
                                    new CipherContext(Map.of("kind", "BUFFERED_BLOCK_CIPHER")))
                            .inBundle(() -> "Bc")
                            .withDependingDetectionRules(BcBufferedBlockCipherInit.rules()));
        }
        return constructorsList;
    }

    private static @Nonnull List<IDetectionRule<Tree>> specialConstructors() {
        List<IDetectionRule<Tree>> constructorsList = new LinkedList<>();

        constructorsList.add(
                new DetectionRuleBuilder<Tree>()
                        .createDetectionRule()
                        .forObjectExactTypes("org.bouncycastle.crypto.modes.NISTCTSBlockCipher")
                        .forConstructor()
                        .shouldBeDetectedAs(new ValueActionFactory<>("NISTCTSBlockCipher"))
                        .withMethodParameter("int")
                        .withMethodParameter("org.bouncycastle.crypto.BlockCipher")
                        .addDependingDetectionRules(BcBlockCipher.all())
                        .buildForContext(new CipherContext(Map.of("kind", "BUFFERED_BLOCK_CIPHER")))
                        .inBundle(() -> "Bc")
                        .withDependingDetectionRules(BcBufferedBlockCipherInit.rules()));

        // This PaddedBufferedBlockCipher constructor has a PKCS7 default padding
        constructorsList.add(
                new DetectionRuleBuilder<Tree>()
                        .createDetectionRule()
                        .forObjectExactTypes(
                                "org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher")
                        .forConstructor()
                        .shouldBeDetectedAs(
                                new ValueActionFactory<>("PaddedBufferedBlockCipher[PKCS7]"))
                        .withMethodParameter("org.bouncycastle.crypto.BlockCipher")
                        .addDependingDetectionRules(BcBlockCipher.all())
                        .buildForContext(new CipherContext(Map.of("kind", "BUFFERED_BLOCK_CIPHER")))
                        .inBundle(() -> "Bc")
                        .withDependingDetectionRules(BcBufferedBlockCipherInit.rules()));

        constructorsList.add(
                new DetectionRuleBuilder<Tree>()
                        .createDetectionRule()
                        .forObjectExactTypes(
                                "org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher")
                        .forConstructor()
                        .shouldBeDetectedAs(new ValueActionFactory<>("PaddedBufferedBlockCipher"))
                        .withMethodParameter("org.bouncycastle.crypto.BlockCipher")
                        .addDependingDetectionRules(BcBlockCipher.all())
                        .withMethodParameter("org.bouncycastle.crypto.paddings.BlockCipherPadding")
                        .addDependingDetectionRules(BcBlockCipherPadding.rules())
                        .buildForContext(new CipherContext(Map.of("kind", "BUFFERED_BLOCK_CIPHER")))
                        .inBundle(() -> "Bc")
                        .withDependingDetectionRules(BcBufferedBlockCipherInit.rules()));

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
