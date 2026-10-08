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
import com.ibm.mapper.model.Padding;
import com.ibm.mapper.model.padding.OAEP;
import com.ibm.mapper.model.padding.PKCS1;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.Optional;
import javax.annotation.Nonnull;

/**
 * Maps the static members of {@code RSAEncryptionPadding} and {@code RSASignaturePadding} to mapper
 * padding nodes.
 *
 * <p>The shared {@code JcaPaddingMapper} cannot be used for these. It recognizes the JCA spelling
 * {@code OAEPWithSHA-256AndMGF1Padding}, whereas .NET writes the same choice as {@code
 * RSAEncryptionPadding.OaepSHA256}, which the engine resolves to the bare member name {@code
 * "OaepSHA256"}. Run through the JCA mapper that name falls through to a raw, uninterpreted padding
 * node, losing both the fact that it is OAEP and which digest it uses.
 *
 * <p>The digest of an OAEP padding is attached to the {@link OAEP} node, so a component encrypted
 * with {@code OaepSHA256} records SHA-256 rather than only "some OAEP". That distinction matters
 * for a bill of materials: {@code OaepSHA1} and {@code OaepSHA256} are the same padding scheme with
 * very different standing.
 *
 * <p>{@code RSASignaturePadding.Pss} has no dedicated padding node in the mapper model, where PSS
 * is represented as the algorithm {@code RSAssaPSS} rather than as a padding. It is therefore
 * recorded as a plain padding named {@code PSS}, which keeps the information present and searchable
 * without inventing a model node.
 *
 * <p>An unrecognized member name yields an empty result rather than a guess.
 */
public final class DotNetPaddingNames {

    private DotNetPaddingNames() {
        // utility
    }

    /**
     * Returns the padding an {@code RSAEncryptionPadding} or {@code RSASignaturePadding} member
     * name denotes, if it is a known one.
     */
    @Nonnull
    public static Optional<INode> parse(
            @Nonnull String paddingName, @Nonnull DetectionLocation detectionLocation) {
        final String name = paddingName.trim();
        if (name.regionMatches(true, 0, "Oaep", 0, 4) && name.length() > 4) {
            return DotNetHashAlgorithmNames.parse(name.substring(4), detectionLocation)
                    .<INode>map(digest -> new OAEP(digest, detectionLocation))
                    .or(() -> Optional.of(new OAEP(detectionLocation)));
        }
        return switch (name.toUpperCase()) {
            case "OAEP" -> Optional.of(new OAEP(detectionLocation));
            case "PKCS1" -> Optional.of(new PKCS1(detectionLocation));
            case "PSS" -> Optional.of(new Padding("PSS", detectionLocation));
            default -> Optional.empty();
        };
    }
}
