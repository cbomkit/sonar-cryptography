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
package com.ibm.plugin.translation.translator.contexts;

import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.algorithms.MD5;
import com.ibm.mapper.model.algorithms.SHA;
import com.ibm.mapper.model.algorithms.SHA2;
import com.ibm.mapper.model.algorithms.SHA3;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.Optional;
import javax.annotation.Nonnull;

/**
 * Maps a {@code System.Security.Cryptography.HashAlgorithmName} to a mapper digest node.
 *
 * <p>{@code HashAlgorithmName} is a struct whose static properties carry the hash identity for a
 * large part of the namespace: the signing and verification methods of {@code RSA}, {@code ECDsa}
 * and {@code DSA}, the PBKDF2 entry points, {@code HKDF}, {@code SP800108HmacCounterKdf} and {@code
 * IncrementalHash.CreateHMAC} all take one. Every one of those call sites needs the same string to
 * node translation, so it lives here once instead of being restated per context translator.
 *
 * <p>The accepted spellings are the member names of {@code HashAlgorithmName} as the detection
 * engine resolves them, which for {@code HashAlgorithmName.SHA256} is the bare member name {@code
 * "SHA256"}. The {@code Name} property of the struct carries the same spelling as a string, so a
 * call site that passes {@code new HashAlgorithmName("SHA256")} resolves identically. An
 * unrecognized name yields an empty result rather than a guessed digest.
 *
 * <p>{@code MD5} and {@code SHA1} are included because they appear in real code and their presence
 * is precisely what a bill of materials needs to record.
 */
public final class DotNetHashAlgorithmNames {

    private DotNetHashAlgorithmNames() {
        // utility
    }

    /** Returns the digest a {@code HashAlgorithmName} member name denotes, if it is a known one. */
    @Nonnull
    public static Optional<MessageDigest> parse(
            @Nonnull String hashAlgorithmName, @Nonnull DetectionLocation detectionLocation) {
        return switch (hashAlgorithmName.toUpperCase().trim()) {
            case "MD5" -> Optional.of(new MD5(detectionLocation));
            case "SHA1", "SHA-1" -> Optional.of(new SHA(detectionLocation));
            case "SHA256", "SHA-256" -> Optional.of(new SHA2(256, detectionLocation));
            case "SHA384", "SHA-384" -> Optional.of(new SHA2(384, detectionLocation));
            case "SHA512", "SHA-512" -> Optional.of(new SHA2(512, detectionLocation));
            case "SHA3_256", "SHA3-256" -> Optional.of(new SHA3(256, detectionLocation));
            case "SHA3_384", "SHA3-384" -> Optional.of(new SHA3(384, detectionLocation));
            case "SHA3_512", "SHA3-512" -> Optional.of(new SHA3(512, detectionLocation));
            default -> Optional.empty();
        };
    }

    /** Same as {@link #parse}, widened to {@link INode} for use in context translators. */
    @Nonnull
    public static Optional<INode> parseAsNode(
            @Nonnull String hashAlgorithmName, @Nonnull DetectionLocation detectionLocation) {
        return parse(hashAlgorithmName, detectionLocation).map(INode.class::cast);
    }
}
