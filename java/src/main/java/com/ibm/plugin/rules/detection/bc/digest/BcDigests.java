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
package com.ibm.plugin.rules.detection.bc.digest;

import com.ibm.engine.model.Size;
import com.ibm.engine.model.context.DigestContext;
import com.ibm.engine.model.context.IDetectionContext;
import com.ibm.engine.model.factory.DigestSizeFactory;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.plugin.rules.detection.Memoize;
import com.ibm.plugin.rules.detection.bc.BouncyCastleInfoMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import java.util.stream.Stream;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.sonar.plugins.java.api.tree.Tree;

public final class BcDigests {

    private BcDigests() {
        // nothing
    }

    private static final BouncyCastleInfoMap infoMap = new BouncyCastleInfoMap();

    static {
        /* Digests with non-standard type */
        infoMap.putKey("KangarooTwelve")
                // The $ indicates a nested class
                .putType("org.bouncycastle.crypto.digests.Kangaroo$");
        infoMap.putKey("MarsupilamiFourteen")
                // The $ indicates a nested class
                .putType("org.bouncycastle.crypto.digests.Kangaroo$");
        infoMap.putKey("KMAC").putType("org.bouncycastle.crypto.macs.");
        infoMap.putKey("LMSContext").putType("org.bouncycastle.pqc.crypto.lms.");

        /*
         * Digests with standard type (in `org.bouncycastle.crypto.digests`):
         * Because several digests below are parent classes of others, but are still public classes with
         * a constructor, we use `forObjectExactTypes` in associated rules otherwise we would have several
         * detections (a class and its parent) instead of one.
         */
        infoMap.putKey("AsconDigest");
        infoMap.putKey("AsconXof");
        infoMap.putKey("Blake2bDigest");
        infoMap.putKey("Blake2bpDigest");
        infoMap.putKey("Blake2sDigest");
        infoMap.putKey("Blake2spDigest");
        infoMap.putKey("Blake2xsDigest");
        infoMap.putKey("Blake3Digest");
        infoMap.putKey("CSHAKEDigest");
        infoMap.putKey("DSTU7564Digest");
        infoMap.putKey("GOST3411_2012_256Digest");
        infoMap.putKey("GOST3411_2012_512Digest");
        infoMap.putKey("GOST3411Digest");
        infoMap.putKey("Haraka256Digest");
        infoMap.putKey("Haraka512Digest");
        infoMap.putKey("HarakaBase");
        infoMap.putKey("ISAPDigest");
        infoMap.putKey("KeccakDigest");
        infoMap.putKey("MD2Digest");
        infoMap.putKey("MD4Digest");
        infoMap.putKey("MD5Digest");
        infoMap.putKey("NullDigest");
        infoMap.putKey("ParallelHash");
        infoMap.putKey("PhotonBeetleDigest");
        infoMap.putKey("RIPEMD128Digest");
        infoMap.putKey("RIPEMD160Digest");
        infoMap.putKey("RIPEMD256Digest");
        infoMap.putKey("RIPEMD320Digest");
        infoMap.putKey("SHA1Digest");
        infoMap.putKey("SHA224Digest");
        infoMap.putKey("SHA256Digest");
        infoMap.putKey("SHA384Digest");
        infoMap.putKey("SHA3Digest");
        infoMap.putKey("SHA512Digest");
        infoMap.putKey("SHA512tDigest");
        infoMap.putKey("SkeinDigest");
        infoMap.putKey("SM3Digest");
        infoMap.putKey("SparkleDigest");
        infoMap.putKey("TigerDigest");
        infoMap.putKey("TupleHash");
        infoMap.putKey("WhirlpoolDigest");
        infoMap.putKey("XoodyakDigest");
    }

    @Nonnull
    private static List<IDetectionRule<Tree>> regularConstructors(
            @Nullable IDetectionContext detectionValueContext) {
        final List<IDetectionRule<Tree>> constructorsList = new LinkedList<>();
        final IDetectionContext context =
                detectionValueContext != null ? detectionValueContext : new DigestContext();

        for (Map.Entry<String, BouncyCastleInfoMap.Info> entry : infoMap.entrySet()) {
            String digest = entry.getKey();
            String digestTypePrefix =
                    entry.getValue().getType() != null
                            ? entry.getValue().getType()
                            : "org.bouncycastle.crypto.digests.";
            constructorsList.add(
                    new DetectionRuleBuilder<Tree>()
                            .createDetectionRule()
                            .forObjectExactTypes(digestTypePrefix + digest)
                            .forConstructor()
                            .shouldBeDetectedAs(new ValueActionFactory<>(digest))
                            // We want to capture all possible constructors (some have arguments)
                            .withAnyParameters()
                            .buildForContext(context)
                            .inBundle(() -> "Bc")
                            .withoutDependingDetectionRules());
        }
        return constructorsList;
    }

    @Nonnull
    private static List<IDetectionRule<Tree>> otherConstructors(
            @Nullable IDetectionContext detectionValueContext) {
        List<IDetectionRule<Tree>> constructorsList = new LinkedList<>();
        IDetectionContext context =
                detectionValueContext != null ? detectionValueContext : new DigestContext();

        constructorsList.add(
                new DetectionRuleBuilder<Tree>()
                        .createDetectionRule()
                        .forObjectExactTypes("org.bouncycastle.crypto.digests.NonMemoableDigest")
                        .forConstructor()
                        .withMethodParameter("org.bouncycastle.crypto.Digest")
                        .addDependingDetectionRules(regularConstructors(detectionValueContext))
                        .buildForContext(context)
                        .inBundle(() -> "Bc")
                        .withoutDependingDetectionRules());

        constructorsList.add(
                new DetectionRuleBuilder<Tree>()
                        .createDetectionRule()
                        .forObjectExactTypes("org.bouncycastle.crypto.digests.ShortenedDigest")
                        .forConstructor()
                        .withMethodParameter("org.bouncycastle.crypto.Digest")
                        .addDependingDetectionRules(regularConstructors(detectionValueContext))
                        .withMethodParameter("int")
                        .shouldBeDetectedAs(new DigestSizeFactory<>(Size.UnitType.BYTE))
                        .buildForContext(context)
                        .inBundle(() -> "Bc")
                        .withoutDependingDetectionRules());

        // add custom constructors for SHAKE to get the digest size
        constructorsList.add(
                new DetectionRuleBuilder<Tree>()
                        .createDetectionRule()
                        .forObjectExactTypes("org.bouncycastle.crypto.digests.SHAKEDigest")
                        .forConstructor()
                        .shouldBeDetectedAs(new ValueActionFactory<>("SHAKEDigest"))
                        .withoutParameters()
                        .buildForContext(context)
                        .inBundle(() -> "Bc")
                        .withoutDependingDetectionRules());

        constructorsList.add(
                new DetectionRuleBuilder<Tree>()
                        .createDetectionRule()
                        .forObjectExactTypes("org.bouncycastle.crypto.digests.SHAKEDigest")
                        .forConstructor()
                        .shouldBeDetectedAs(new ValueActionFactory<>("SHAKEDigest"))
                        .withMethodParameter("int")
                        .shouldBeDetectedAs(new DigestSizeFactory<>(Size.UnitType.BIT))
                        .asChildOfParameterWithId(-1)
                        .buildForContext(context)
                        .inBundle(() -> "Bc")
                        .withoutDependingDetectionRules());

        return constructorsList;
    }

    private static final Supplier<List<IDetectionRule<Tree>>> RULES =
            Memoize.of(() -> buildRules(null));

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return RULES.get();
    }

    @Nonnull
    public static List<IDetectionRule<Tree>> rules(
            @Nullable IDetectionContext detectionValueContext) {
        return detectionValueContext == null ? RULES.get() : buildRules(detectionValueContext);
    }

    @Nonnull
    private static List<IDetectionRule<Tree>> buildRules(
            @Nullable IDetectionContext detectionValueContext) {
        return Stream.concat(
                        regularConstructors(detectionValueContext).stream(),
                        otherConstructors(detectionValueContext).stream())
                .toList();
    }
}
