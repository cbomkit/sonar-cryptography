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
import com.ibm.mapper.model.DigestSize;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.IPrimitive;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.PublicKeyEncryption;
import com.ibm.mapper.reorganizer.IReorganizerRule;
import com.ibm.mapper.reorganizer.UsualPerformActions;
import com.ibm.mapper.reorganizer.builder.ReorganizerRuleBuilder;
import java.util.List;
import javax.annotation.Nonnull;

public final class AsymmetricBlockCipherReorganizer {

    private AsymmetricBlockCipherReorganizer() {
        // private
    }

    @Nonnull
    public static final IReorganizerRule MERGE_PKE_PARENT_AND_CHILD =
            new ReorganizerRuleBuilder()
                    .createReorganizerRule()
                    .forNodeKind(PublicKeyEncryption.class)
                    .forNodeValue(ITranslator.UNKNOWN)
                    .includingChildren(
                            List.of(
                                    new ReorganizerRuleBuilder()
                                            .createReorganizerRule()
                                            .forNodeKind(PublicKeyEncryption.class)
                                            .noAction()))
                    .perform(
                            UsualPerformActions.performMergeParentAndChildOfSameKind(
                                    PublicKeyEncryption.class));

    /**
     * A reorganizer rule that merges an algorithm of the given kind with a child that is the same
     * algorithm, e.g. a DH key generated for DH parameters described in more detail by the child.
     * The child takes the place of the parent and receives the parent's other children.
     */
    @Nonnull
    public static IReorganizerRule mergeParentAndChildOfSameAlgorithm(
            @Nonnull Class<? extends IPrimitive> kind) {
        return new ReorganizerRuleBuilder()
                .createReorganizerRule("MERGE_PARENT_AND_CHILD_OF_SAME_ALGORITHM")
                .forNodeKind(kind)
                .withDetectionCondition(
                        (node, parent, roots) ->
                                node.hasChildOfType(kind)
                                        .map(child -> child.getClass().equals(node.getClass()))
                                        .orElse(false))
                .perform(UsualPerformActions.performMergeParentAndChildOfSameKind(kind));
    }

    @Nonnull
    public static final IReorganizerRule INVERT_DIGEST_AND_ITS_SIZE =
            new ReorganizerRuleBuilder()
                    .createReorganizerRule()
                    .forNodeKind(DigestSize.class)
                    .includingChildren(
                            List.of(
                                    new ReorganizerRuleBuilder()
                                            .createReorganizerRule()
                                            .forNodeKind(MessageDigest.class)
                                            .noAction()))
                    .perform(
                            (digestSizeNode, parent, roots) -> {
                                if (parent == null) {
                                    // Do nothing
                                    return roots;
                                }

                                INode messageDigestChild =
                                        digestSizeNode.getChildren().get(MessageDigest.class);

                                /* Append the DigestSize (without its DigestSize) child to the new DigestSize */
                                digestSizeNode.removeChildOfType(MessageDigest.class);
                                messageDigestChild.put(digestSizeNode);

                                // Remove the DigestSize from the parent
                                parent.removeChildOfType(DigestSize.class);

                                // Append the MessageDigest to the parent
                                parent.put(messageDigestChild);
                                return roots;
                            });
}
