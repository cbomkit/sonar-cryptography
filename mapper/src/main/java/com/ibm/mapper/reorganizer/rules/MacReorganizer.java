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

import com.ibm.mapper.ITranslator;
import com.ibm.mapper.model.Algorithm;
import com.ibm.mapper.model.AuthenticatedEncryption;
import com.ibm.mapper.model.BlockCipher;
import com.ibm.mapper.model.BlockSize;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.Mac;
import com.ibm.mapper.model.Mode;
import com.ibm.mapper.model.Oid;
import com.ibm.mapper.model.Padding;
import com.ibm.mapper.model.StreamCipher;
import com.ibm.mapper.model.TagLength;
import com.ibm.mapper.model.algorithms.GMAC;
import com.ibm.mapper.reorganizer.IReorganizerRule;
import com.ibm.mapper.reorganizer.UsualPerformActions;
import com.ibm.mapper.reorganizer.builder.ReorganizerRuleBuilder;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import javax.annotation.Nonnull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public final class MacReorganizer {
    private static final Logger LOGGER = LoggerFactory.getLogger(MacReorganizer.class);

    private MacReorganizer() {
        // private
    }

    @Nonnull
    public static final IReorganizerRule MERGE_UNKNOWN_MAC_PARENT_AND_CIPHER_CHILD =
            new ReorganizerRuleBuilder()
                    .createReorganizerRule()
                    .forNodeKind(Mac.class)
                    .forNodeValue(ITranslator.UNKNOWN)
                    .includingChildren(
                            List.of(
                                    new ReorganizerRuleBuilder()
                                            .createReorganizerRule()
                                            .forNodeKind(BlockCipher.class)
                                            .noAction()))
                    .perform(
                            (node, parent, roots) -> {
                                Algorithm blockCipher =
                                        (Algorithm) node.getChildren().get(BlockCipher.class);
                                INode newMac = blockCipher.asKind(Mac.class);

                                for (Map.Entry<Class<? extends INode>, INode> childKeyValue :
                                        node.getChildren().entrySet()) {
                                    if (!childKeyValue.getKey().equals(BlockCipher.class)) {
                                        newMac.put(childKeyValue.getValue());
                                    }
                                }

                                if (parent == null) {
                                    // `node` is a root node
                                    // Create a copy of the roots list
                                    List<INode> rootsCopy = new ArrayList<>(roots);
                                    for (int i = 0; i < rootsCopy.size(); i++) {
                                        if (rootsCopy.get(i) == node) {
                                            rootsCopy.set(i, newMac);
                                            break;
                                        }
                                    }
                                    return rootsCopy;
                                } else {
                                    // Replace the previous PublicKeyEncryption node
                                    parent.put(newMac);
                                    return roots;
                                }
                            });

    /**
     * A GMAC whose cipher is given separately as a cipher in GCM mode (e.g. OpenSSL's {@code
     * EVP_MAC_fetch(..., "GMAC", ...)} with the {@code "cipher"} parameter {@code "AES-128-GCM"})
     * becomes that cipher as a {@code Mac} in GMAC mode ({@code AES-128-GMAC}), the same shape as a
     * GMAC built on a block cipher. The cipher is a {@code BlockCipher} or, once enriched, an
     * {@code AuthenticatedEncryption}; its GCM mode and OID do not apply to the MAC and are
     * dropped.
     */
    @Nonnull
    public static final IReorganizerRule MERGE_GMAC_PARENT_AND_GCM_CIPHER_CHILD =
            new ReorganizerRuleBuilder()
                    .createReorganizerRule()
                    .forNodeKind(Mac.class)
                    .forNodeValue(GMAC.NAME)
                    .withAnyNonNullChildren()
                    .withDetectionCondition((node, parent, roots) -> gmacCipher(node).isPresent())
                    .perform(
                            UsualPerformActions.performReplacingNode(
                                    (node, parent, roots) -> {
                                        INode cipher = gmacCipher(node).orElseThrow();
                                        node.removeChildOfType(cipher.getKind());
                                        Algorithm mac = ((Algorithm) cipher).asKind(Mac.class);
                                        mac.removeChildOfType(Mode.class);
                                        mac.removeChildOfType(Oid.class);
                                        mac.put(
                                                new com.ibm.mapper.model.mode.GMAC(
                                                        mac.getDetectionContext()));
                                        return mac;
                                    }));

    /** The cipher of a GMAC: a child block cipher or authenticated encryption. */
    @Nonnull
    private static Optional<INode> gmacCipher(@Nonnull INode gmac) {
        return gmac.hasChildOfType(BlockCipher.class)
                .or(() -> gmac.hasChildOfType(AuthenticatedEncryption.class));
    }

    /**
     * A reorganizer rule for moving cipher configuration nodes (e.g., Mode, Padding, BlockSize)
     * under their respective cipher parent nodes (BlockCipher or StreamCipher) within a {@code Mac}
     * node.
     *
     * <p>This rule is designed to enforce a hierarchical structure where cryptographic
     * configuration parameters such as {@code Mode}, {@code Padding}, and {@code BlockSize} are
     * directly associated with their corresponding cipher (either a {@code BlockCipher} or {@code
     * StreamCipher}), rather than being children of the {@code Mac} node.
     */
    @Nonnull
    public static final IReorganizerRule MOVE_SOME_MAC_CHILDREN_UNDER_BLOCKCIPHER =
            new ReorganizerRuleBuilder()
                    .createReorganizerRule()
                    .forNodeKind(Mac.class)
                    .withDetectionCondition(
                            (node, parent, roots) -> {
                                return (node.hasChildOfType(BlockCipher.class).isPresent()
                                                || node.hasChildOfType(StreamCipher.class)
                                                        .isPresent())
                                        && (node.hasChildOfType(Mode.class).isPresent()
                                                || node.hasChildOfType(Padding.class).isPresent()
                                                || node.hasChildOfType(BlockSize.class)
                                                        .isPresent());
                            })
                    .perform(
                            (node, parent, roots) -> {
                                INode cipherParent = null;
                                for (Map.Entry<Class<? extends INode>, INode> entry :
                                        node.getChildren().entrySet()) {
                                    Class<? extends INode> kind = entry.getKey();
                                    if (kind.equals(BlockCipher.class)
                                            || kind.equals(StreamCipher.class)) {
                                        if (cipherParent != null) {
                                            // Detect when there are mutliple cipher parents
                                            LOGGER.warn(
                                                    "A Mac node has both BlockCipher and StreamCipher children");
                                        }
                                        cipherParent = entry.getValue();
                                    }
                                }
                                if (cipherParent == null) {
                                    // Do nothing
                                    return roots;
                                }

                                for (Iterator<Map.Entry<Class<? extends INode>, INode>> iterator =
                                                node.getChildren().entrySet().iterator();
                                        iterator.hasNext(); ) {
                                    Map.Entry<Class<? extends INode>, INode> entry =
                                            iterator.next();
                                    Class<? extends INode> kind = entry.getKey();
                                    if (kind.equals(Mode.class)
                                            || kind.equals(Padding.class)
                                            || kind.equals(BlockSize.class)) {
                                        INode child = entry.getValue();
                                        // Append the child to `cipherParent`
                                        // (only when `cipherParent` does not already have such a
                                        // child)
                                        if (cipherParent.hasChildOfType(kind).isEmpty()) {
                                            cipherParent.put(child);
                                        }
                                        // Remove the entry from iterator (to avoid concurrency
                                        // issues)
                                        iterator.remove();
                                        // Remove the child from the current `node`
                                        node.removeChildOfType(kind);
                                    }
                                }
                                return roots;
                            });

    @Nonnull
    public static final IReorganizerRule MOVE_TAG_LENGTH_UNDER_MAC =
            new ReorganizerRuleBuilder()
                    .createReorganizerRule()
                    .forNodeKind(Mac.class)
                    .withDetectionCondition(
                            (node, parent, roots) ->
                                    parent != null
                                            && parent.hasChildOfType(TagLength.class).isPresent())
                    .perform(
                            (node, parent, roots) -> {
                                if (parent == null) {
                                    return roots;
                                }
                                INode tagLengthChild = parent.getChildren().get(TagLength.class);

                                // Append the TagLength to the Mac node and remove it from the
                                // parent node
                                node.put(tagLengthChild);
                                parent.removeChildOfType(TagLength.class);
                                return roots;
                            });
}
