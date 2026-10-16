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
package com.ibm.mapper.reorganizer.rules;

import com.ibm.mapper.model.DigestSize;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.algorithms.SHA2;
import com.ibm.mapper.reorganizer.IReorganizerRule;
import com.ibm.mapper.reorganizer.builder.ReorganizerRuleBuilder;
import java.util.LinkedList;
import java.util.List;
import java.util.Optional;
import javax.annotation.Nonnull;

public final class MessageDigestReorganizer {

    private MessageDigestReorganizer() {
        // private
    }

    /**
     * Handles {@code SHA512.new(truncate=N)}: when a SHA-512 {@link MessageDigest} node carries a
     * {@link DigestSize} child whose value differs from 512 (the truncation value), replace the
     * node with a {@code SHA2(N, SHA2(512, ...))} structure, mirroring the JCA pattern for {@code
     * "SHA-512/224"} / {@code "SHA-512/256"}.
     */
    @Nonnull
    public static final IReorganizerRule WRAP_SHA512_TRUNCATED =
            new ReorganizerRuleBuilder()
                    .createReorganizerRule("WRAP_SHA512_TRUNCATED")
                    .forNodeKind(MessageDigest.class)
                    .withDetectionCondition(
                            (node, parent, roots) -> {
                                if (!"SHA-512".equals(node.asString())) {
                                    return false;
                                }
                                return node.hasChildOfType(DigestSize.class)
                                        .filter(ds -> !"512".equals(ds.asString()))
                                        .isPresent();
                            })
                    .perform(
                            (node, parent, roots) -> {
                                if (!(node instanceof SHA2 sha2Node)) {
                                    return roots;
                                }
                                final Optional<INode> digestSizeOpt =
                                        sha2Node.hasChildOfType(DigestSize.class);
                                if (digestSizeOpt.isEmpty()) {
                                    return roots;
                                }
                                final int truncateSize =
                                        ((DigestSize) digestSizeOpt.get()).getValue();
                                final SHA2 preHash512 =
                                        new SHA2(512, sha2Node.getDetectionContext());
                                final SHA2 truncated =
                                        new SHA2(
                                                truncateSize,
                                                preHash512,
                                                sha2Node.getDetectionContext());

                                // Copy remaining children (BlockSize, OID, Digest, …) onto the
                                // new truncated node, skipping DigestSize (already set by SHA2
                                // constructor) and the SHA2(512) pre-hash.
                                sha2Node.getChildren().values().stream()
                                        .filter(child -> !(child instanceof DigestSize))
                                        .filter(child -> !(child instanceof MessageDigest))
                                        .forEach(truncated::put);

                                if (parent != null) {
                                    parent.put(truncated);
                                    return roots;
                                }
                                // Root node replacement
                                final List<INode> newRoots = new LinkedList<>(roots);
                                newRoots.replaceAll(r -> r == node ? truncated : r);
                                return newRoots;
                            });
}
