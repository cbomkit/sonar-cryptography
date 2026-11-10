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
package com.ibm.plugin.rules.detection.dcm4che;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import javax.annotation.Nonnull;

/**
 * The dcm4che jars the verifier needs on the classpath, and whether this build has them.
 *
 * <p>Unlike {@code BouncyCastleJars}, these are <em>not</em> checked in. Bouncy Castle is
 * MIT-style, so carrying its jar costs nothing; dcm4che is MPL 1.1 / GPL 2.0 / LGPL 2.1, and a copy
 * in this Apache-2.0 repository would be redistribution of an MPL-covered binary, which carries a
 * source-availability obligation. {@code java/pom.xml} fetches them from {@code maven.dcm4che.org}
 * into {@code target/test-jars} instead, so the developer and CI obtain them from dcm4che and this
 * project redistributes nothing.
 *
 * <p>The fetch is deliberately allowed to fail. An offline or network-restricted build skips the
 * download, {@link #available()} then returns {@code false}, and the two dcm4che test classes
 * report as skipped rather than failing -- a missing optional fixture must not turn a green build
 * red.
 *
 * <p>Which also means the jars have to be pinned by content rather than by URL, because a build can
 * no longer be trusted to have obtained anything in particular: a truncated download, a changed
 * upstream artifact or a substituted one would otherwise be used as if it were the pinned version.
 * A file whose digest does not match is treated exactly like a missing one.
 */
public class Dcm4cheJars {

    private Dcm4cheJars() {
        // utility
    }

    private static final String VERSION = "5.35.2";

    /** From https://maven.dcm4che.org/org/dcm4che/, SHA-256 of the published artifacts. */
    @Nonnull
    private static final Map<String, String> DIGESTS =
            Map.of(
                    "dcm4che-net-" + VERSION + ".jar",
                            "40d17b06339e08a2341b2d9785014fdc047b79bb04d25f8f7267df58cff85bd6",
                    "dcm4che-core-" + VERSION + ".jar",
                            "f660d2aa8dbcabda1d0051431d9c39ff39453de9e7541b227de8aa1a900441a8");

    /** {@code dcm4che-core} comes along because {@code Connection} refers to it. */
    public static final Collection<File> dcm4che5352Jars =
            List.of(
                    new File("target/test-jars/dcm4che-net-" + VERSION + ".jar"),
                    new File("target/test-jars/dcm4che-core-" + VERSION + ".jar"));

    public static final Collection<File> latestJars = dcm4che5352Jars;

    /**
     * Whether every jar is present and is the pinned artifact.
     *
     * <p>Used from an {@code assumeTrue} so that a build without them skips the dcm4che tests. A
     * type the semantic model cannot complete is a type the rules cannot match, so running them
     * against a missing classpath would assert the absence of findings that the rules do in fact
     * produce -- a false green, which is worse than a skip.
     */
    public static boolean available() {
        return latestJars.stream().allMatch(Dcm4cheJars::isPinnedArtifact);
    }

    /** The message an {@code assumeTrue} prints when the jars are not there. */
    @Nonnull
    public static String unavailableReason() {
        return "the dcm4che test jars are not in target/test-jars; run `mvn -pl java"
                + " generate-test-resources` with network access to fetch them";
    }

    private static boolean isPinnedArtifact(@Nonnull File jar) {
        if (!jar.isFile()) {
            return false;
        }
        final String expected = DIGESTS.get(jar.getName());
        return expected != null && expected.equals(sha256(jar));
    }

    @Nonnull
    private static String sha256(@Nonnull File file) {
        try {
            final MessageDigest digest = MessageDigest.getInstance("SHA-256");
            final byte[] hash = digest.digest(Files.readAllBytes(file.toPath()));
            final StringBuilder hex = new StringBuilder(hash.length * 2);
            for (byte b : hash) {
                hex.append(Character.forDigit((b >> 4) & 0xF, 16));
                hex.append(Character.forDigit(b & 0xF, 16));
            }
            return hex.toString();
        } catch (IOException | NoSuchAlgorithmException e) {
            return "";
        }
    }
}
