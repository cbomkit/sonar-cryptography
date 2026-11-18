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
package com.ibm.plugin.translation.reorganizer;

import com.ibm.mapper.model.DigestSize;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.Oid;
import com.ibm.mapper.model.algorithms.SHA2;
import com.ibm.mapper.reorganizer.IReorganizerRule;
import com.ibm.mapper.reorganizer.builder.ReorganizerRuleBuilder;
import com.ibm.plugin.translation.model.Sha512Truncation;
import java.util.LinkedList;
import java.util.List;
import java.util.Optional;
import javax.annotation.Nonnull;

public final class PythonDigestReorganizer {

    private PythonDigestReorganizer() {
        // private
    }

    private static Optional<Sha512Truncation> truncationOf(@Nonnull INode node) {
        return node.hasChildOfType(Sha512Truncation.class)
                .filter(Sha512Truncation.class::isInstance)
                .map(Sha512Truncation.class::cast)
                .filter(truncation -> Sha512Truncation.isSupported(truncation.getValue()));
    }

    /**
     * Handles {@code SHA512.new(truncate="224" | "256")}: a SHA-512 node carrying a {@link
     * Sha512Truncation} marker is replaced by {@code SHA2(N, SHA2(512))}, i.e. SHA-512/224 or
     * SHA-512/256. The marker is consumed and the plain SHA-512 node is not left behind.
     */
    @Nonnull
    public static final IReorganizerRule WRAP_SHA512_TRUNCATED =
            new ReorganizerRuleBuilder()
                    .createReorganizerRule("WRAP_SHA512_TRUNCATED")
                    .forNodeKind(MessageDigest.class)
                    .withDetectionCondition(
                            (node, parent, roots) ->
                                    node instanceof SHA2
                                            && "SHA-512".equals(node.asString())
                                            && truncationOf(node).isPresent())
                    .perform(
                            (node, parent, roots) -> {
                                final Optional<Sha512Truncation> truncation = truncationOf(node);
                                if (truncation.isEmpty() || !(node instanceof SHA2 sha512)) {
                                    return roots;
                                }
                                final SHA2 truncated =
                                        new SHA2(
                                                truncation.get().getValue(),
                                                new SHA2(512, sha512.getDetectionContext()),
                                                sha512.getDetectionContext());

                                // Transfer unrelated children (e.g. functionalities). The digest
                                // size, the nested pre-hash and the OID of SHA-512 must not
                                // override the ones of the variant; the marker is consumed.
                                sha512.getChildren().values().stream()
                                        .filter(child -> !(child instanceof DigestSize))
                                        .filter(child -> !(child instanceof MessageDigest))
                                        .filter(child -> !(child instanceof Oid))
                                        .filter(child -> !(child instanceof Sha512Truncation))
                                        .forEach(truncated::put);

                                if (parent != null) {
                                    parent.put(truncated);
                                    return roots;
                                }
                                final List<INode> newRoots = new LinkedList<>(roots);
                                newRoots.replaceAll(root -> root == node ? truncated : root);
                                return newRoots;
                            });
}
