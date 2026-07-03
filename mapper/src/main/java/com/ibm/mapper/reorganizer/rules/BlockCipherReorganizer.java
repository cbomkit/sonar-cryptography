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

import com.ibm.mapper.model.Algorithm;
import com.ibm.mapper.model.BlockCipher;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.reorganizer.IReorganizerRule;
import com.ibm.mapper.reorganizer.UsualPerformActions;
import com.ibm.mapper.reorganizer.builder.ReorganizerRuleBuilder;
import java.util.ArrayList;
import java.util.List;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public final class BlockCipherReorganizer {

    private BlockCipherReorganizer() {
        // private
    }

    public static final IReorganizerRule MERGE_BLOCK_CIPHER_PARENT_AND_CHILD =
            new ReorganizerRuleBuilder()
                    .createReorganizerRule()
                    .forNodeKind(BlockCipher.class)
                    .includingChildren(
                            List.of(
                                    new ReorganizerRuleBuilder()
                                            .createReorganizerRule()
                                            .forNodeKind(BlockCipher.class)
                                            .noAction()))
                    .perform(
                            UsualPerformActions.performMergeParentAndChildOfSameKind(
                                    BlockCipher.class));

    public static final IReorganizerRule DEDUPLICATE_OVERLAPPING_ROOTS =
            new IReorganizerRule() {
                @Override
                public boolean match(
                        @Nonnull INode node, @Nonnull INode parent, @Nonnull List<INode> roots) {
                    if (!roots.contains(node) || !(node instanceof Algorithm algA)) {
                        return false;
                    }

                    for (INode other : roots) {
                        if (other != node && other instanceof Algorithm algB) {
                            if (algA.getDetectionContext().equals(algB.getDetectionContext())
                                    && isRelatedCipherFamily(algA.getName(), algB.getName())) {
                                return true;
                            }
                        }
                    }
                    return false;
                }

                @Nullable @Override
                public List<INode> applyReorganization(
                        @Nonnull INode node, @Nonnull INode parent, @Nonnull List<INode> roots) {
                    if (!(node instanceof Algorithm)) {
                        return roots;
                    }

                    List<INode> newRoots = new ArrayList<>(roots);
                    INode currentBase = node;
                    boolean merged;
                    do {
                        merged = false;
                        INode toRemove = null;
                        INode toKeep = null;

                        for (INode other : newRoots) {
                            if (other != currentBase && other instanceof Algorithm algB) {
                                Algorithm baseAlg = (Algorithm) currentBase;

                                if (baseAlg.getDetectionContext().equals(algB.getDetectionContext())
                                        && isRelatedCipherFamily(
                                                baseAlg.getName(), algB.getName())) {

                                    String nameA = baseAlg.getName().trim();
                                    String nameB = algB.getName().trim();

                                    if (nameA.equalsIgnoreCase("Unknown") || nameA.isEmpty()) {
                                        toKeep = other;
                                        toRemove = currentBase;
                                    } else if (nameB.equalsIgnoreCase("Unknown")
                                            || nameB.isEmpty()) {
                                        toKeep = currentBase;
                                        toRemove = other;
                                    } else if (nameA.length() >= nameB.length()) {
                                        toKeep = currentBase;
                                        toRemove = other;
                                    } else {
                                        toKeep = other;
                                        toRemove = currentBase;
                                    }
                                    break;
                                }
                            }
                        }

                        if (toRemove != null) {
                            // Merge non-conflicting children from the removed node into the
                            // retained node. Existing children take precedence when both
                            // nodes contain the same child kind.
                            for (INode child : toRemove.getChildren().values()) {
                                if (!toKeep.getChildren().containsKey(child.getKind())) {
                                    toKeep.put(child);
                                }
                            }
                            newRoots.remove(toRemove);
                            currentBase = toKeep;
                            merged = true;
                        }
                    } while (merged);

                    return newRoots;
                }

                private boolean isRelatedCipherFamily(String nameA, String nameB) {
                    String safeA =
                            (nameA != null && !nameA.trim().isEmpty())
                                    ? nameA.trim().toUpperCase()
                                    : "UNKNOWN";
                    String safeB =
                            (nameB != null && !nameB.trim().isEmpty())
                                    ? nameB.trim().toUpperCase()
                                    : "UNKNOWN";

                    if (safeA.equals("UNKNOWN") || safeB.equals("UNKNOWN")) {
                        return true;
                    }

                    String shorter = safeA.length() < safeB.length() ? safeA : safeB;
                    String longer = safeA.length() < safeB.length() ? safeB : safeA;

                    if (shorter.equals(longer)) {
                        return true;
                    }

                    if (longer.startsWith(shorter)) {
                        char nextChar = longer.charAt(shorter.length());
                        // Require a non-alphanumeric separator after the shared prefix to
                        // avoid false-positive matches between unrelated algorithm names.
                        return !Character.isLetterOrDigit(nextChar);
                    }

                    return false;
                }

                @Nonnull
                @Override
                public String asString() {
                    return "DEDUPLICATE_OVERLAPPING_ROOTS";
                }

                @Nonnull
                @Override
                public Class<? extends INode> getNodeKind() {
                    return BlockCipher.class;
                }
            };
}
