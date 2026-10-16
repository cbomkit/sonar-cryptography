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

import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.Padding;
import com.ibm.mapper.model.PrivateKey;
import com.ibm.mapper.model.PublicKeyEncryption;
import com.ibm.mapper.model.functionality.Decrypt;
import com.ibm.mapper.model.padding.OAEP;
import com.ibm.mapper.reorganizer.IReorganizerRule;
import com.ibm.mapper.reorganizer.builder.ReorganizerRuleBuilder;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public final class PaddingReorganizer {

    private PaddingReorganizer() {
        // nothing
    }

    public static final IReorganizerRule MOVE_OAEP_UNDER_ALGORITHM =
            new ReorganizerRuleBuilder()
                    .createReorganizerRule()
                    .forNodeKind(PrivateKey.class)
                    .withDetectionCondition(
                            (node, parent, roots) -> {
                                final Optional<INode> functionality =
                                        node.hasChildOfType(Decrypt.class);
                                final Optional<INode> pke =
                                        node.hasChildOfType(PublicKeyEncryption.class);
                                if (functionality.isEmpty()) {
                                    return false;
                                }
                                if (pke.isEmpty()) {
                                    return false;
                                }

                                return functionality
                                        .get()
                                        .hasChildOfType(Padding.class)
                                        .map(OAEP.class::isInstance)
                                        .orElse(false);
                            })
                    .perform(
                            (node, parent, roots) -> {
                                final Optional<INode> pke =
                                        node.hasChildOfType(PublicKeyEncryption.class);
                                final Optional<INode> functionality =
                                        node.hasChildOfType(Decrypt.class);
                                if (functionality.isEmpty()) {
                                    return roots;
                                }
                                if (pke.isEmpty()) {
                                    return roots;
                                }

                                functionality
                                        .get()
                                        .hasChildOfType(Padding.class)
                                        .ifPresent(
                                                p -> {
                                                    pke.get().put(p);
                                                    functionality
                                                            .get()
                                                            .removeChildOfType(p.getKind());
                                                });
                                return roots;
                            });

    /**
     * Lifts a padding from a functionality node onto the algorithm it describes.
     *
     * <p>{@link #MOVE_OAEP_UNDER_ALGORITHM} does the same for one specific JCA tree. This is the
     * general form, because .NET names the padding on the operation rather than on the creation
     * ({@code rsa.Decrypt(data, RSAEncryptionPadding.OaepSHA1)}) and so produces it under a
     * functionality node, two shapes deep:
     *
     * <ul>
     *   <li>the algorithm is the root and the operation hangs under it, or
     *   <li>a key is the root and the operation and the algorithm are siblings under it, which is
     *       what a key taken from an X.509 certificate looks like.
     * </ul>
     *
     * <p>{@code AlgorithmComponentBuilder} reads the padding from the algorithm's direct children
     * only, so without this the padding never reaches the CBOM: the component comes out as a bare
     * {@code RSA} with no padding, while the padding's own digest is still emitted as a dependency
     * — leaving a SHA-1 component beside an RSA component with nothing to explain why it is there.
     *
     * @param holder the node kind that carries the functionality
     * @param functionality the functionality node kind to take the padding from
     */
    @Nonnull
    public static IReorganizerRule movePaddingToAlgorithm(
            @Nonnull Class<? extends INode> holder, @Nonnull Class<? extends INode> functionality) {
        return new ReorganizerRuleBuilder()
                .createReorganizerRule()
                .forNodeKind(holder)
                .withDetectionCondition(
                        (node, parent, roots) ->
                                targetAlgorithm(node) != null
                                        && node.hasChildOfType(functionality)
                                                .map(
                                                        f ->
                                                                f.hasChildOfType(Padding.class)
                                                                        .isPresent())
                                                .orElse(false))
                .perform(
                        (node, parent, roots) -> {
                            final INode algorithm = targetAlgorithm(node);
                            if (algorithm == null) {
                                return roots;
                            }
                            node.hasChildOfType(functionality)
                                    .flatMap(
                                            f ->
                                                    f.hasChildOfType(Padding.class)
                                                            .map(
                                                                    padding ->
                                                                            new INode[] {
                                                                                f, padding
                                                                            }))
                                    .ifPresent(
                                            pair -> {
                                                algorithm.put(pair[1]);
                                                pair[0].removeChildOfType(pair[1].getKind());
                                            });
                            return roots;
                        });
    }

    /**
     * The algorithm a padding found under {@code holder} belongs to: the holder itself when it is
     * the algorithm, otherwise the algorithm it wraps. Returns {@code null} when there is none, in
     * which case the padding is left alone rather than attached to something else.
     */
    @Nullable private static INode targetAlgorithm(@Nonnull INode holder) {
        if (holder.is(PublicKeyEncryption.class)) {
            return holder;
        }
        return holder.hasChildOfType(PublicKeyEncryption.class).orElse(null);
    }
}
