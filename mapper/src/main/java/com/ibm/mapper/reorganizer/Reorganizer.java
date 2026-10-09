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
package com.ibm.mapper.reorganizer;

import com.ibm.mapper.model.INode;
import java.util.IdentityHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.apache.commons.lang3.tuple.Pair;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public final class Reorganizer implements IReorganizer {
    private static final Logger LOGGER = LoggerFactory.getLogger(Reorganizer.class);

    // Maximum number of reorganization steps (to prevent infinite loops)
    private static final int MAX_ITERATIONS = 10;

    private final List<IReorganizerRule> rules;
    private final Map<INode, IReorganizerRule> alreadyAppliedRules;

    public Reorganizer(@Nonnull List<IReorganizerRule> rules) {
        this.rules = rules;
        // by identity: equal nodes of different trees (e.g. the copies of a root made for each
        // value of a property) are reorganized each
        this.alreadyAppliedRules = new IdentityHashMap<>();
    }

    @Override
    @Nonnull
    public List<INode> reorganize(@Nonnull final List<INode> rootNodes) {
        final List<INode> reorganizedNodes = this.reorganize(rootNodes, 0);
        this.alreadyAppliedRules.forEach(
                (node, rule) -> {
                    String message =
                            String.format(
                                    "[reorganizer] MATCH: Node '%s' with rule %s",
                                    node.asString(), rule.asString());
                    LOGGER.debug(message);
                });
        return reorganizedNodes;
    }

    @Nonnull
    private List<INode> reorganize(@Nonnull final List<INode> rootNodes, int iterations) {
        /*
         * Idea: We iterate on all nodes of the tree with a BFS (done by `reorganizeRecursive`),
         * and we check for each node if it matches with a reorganization rule (in `applyReorganizerRules`).
         * If it matches, we apply the reorganization and return the updated list of root nodes of the
         * translation tree. We continue the BFS with the new nodes instead of restarting from the beginning.
         * This process ends once no reorganization rule matches with the current translation tree. When
         * this is the case, `reorganizeRecursive` returns an empty Optional, which is our condition to
         * stop the while loop defined in `reorganize`.
         */
        List<INode> currentRootNodes = rootNodes;
        Optional<List<INode>> newRootNodes = Optional.of(rootNodes);
        while (newRootNodes.isPresent() && iterations < MAX_ITERATIONS) {
            currentRootNodes = newRootNodes.get();
            newRootNodes =
                    reorganizeRecursive(
                            currentRootNodes.stream()
                                    .map(childNode -> Pair.<INode, INode>of(childNode, null))
                                    .toList(),
                            currentRootNodes,
                            iterations);
            iterations += 1;
        }
        if (iterations == MAX_ITERATIONS) {
            return currentRootNodes;
        }
        return currentRootNodes;
    }

    /**
     * Check the given nodes for a match with reorganizer rules, and apply the reorganization of the
     * first match. If no match happens, recursively continue with the children of all the nodes.
     *
     * @param currentNodeParentPairs - Pairs of nodes with their parent node (if a node is a root
     *     node, its parent is {@code null})
     * @param rootNodes - Root nodes of the translation tree
     * @return Optional containing the new root nodes of the translation tree if a reorganization
     *     has occurred, empty Optional otherwise
     */
    @Nonnull
    private Optional<List<INode>> reorganizeRecursive(
            @Nonnull final List<Pair<INode, INode>> currentNodeParentPairs,
            @Nonnull final List<INode> rootNodes,
            int iterations) {
        List<Pair<INode, INode>> nextPairs = new LinkedList<>();
        for (Pair<INode, INode> pair : currentNodeParentPairs) {
            final INode node = pair.getLeft();
            final INode parent = pair.getRight();
            final Optional<List<INode>> optionalUpdatedRootNodes =
                    applyReorganizerRules(node, parent, rootNodes, iterations);
            if (optionalUpdatedRootNodes.isPresent()) {
                return optionalUpdatedRootNodes;
            }
            nextPairs.addAll(
                    node.getChildren().values().stream()
                            .map(childNode -> Pair.of(childNode, node))
                            .toList());
        }
        if (nextPairs.isEmpty()) {
            return Optional.empty();
        }
        return reorganizeRecursive(nextPairs, rootNodes, iterations);
    }

    /**
     * Check if {@code node} matches with any reorganization rule, and apply the reorganization of
     * the first match.
     *
     * @param node - the current node
     * @param parent - Parent of {@code node}, or {@code null} if {@code node} is a root node
     * @param rootNodes - Root nodes of the translation tree
     * @return Optional containing the new root nodes of the translation tree if a reorganization
     *     has occured, empty Optional otherwise
     */
    @Nonnull
    private Optional<List<INode>> applyReorganizerRules(
            @Nonnull INode node,
            @Nonnull INode parent,
            @Nonnull final List<INode> rootNodes,
            int iterations) {
        for (IReorganizerRule reorganizerRule : this.rules) {
            if (this.alreadyAppliedRules.containsKey(node)
                    && this.alreadyAppliedRules.get(node).equals(reorganizerRule)) {
                continue;
            }
            if (reorganizerRule.match(node, parent, rootNodes)) {
                this.alreadyAppliedRules.put(node, reorganizerRule);
                @Nullable final List<INode> newRootNodes =
                        reorganizerRule.applyReorganization(node, parent, rootNodes);
                // the recursion helps to apply reorganizer rules based on the result of the
                // previous
                return Optional.of(
                        this.reorganize(
                                Objects.requireNonNullElse(newRootNodes, rootNodes),
                                iterations + 1));
            }
        }
        return Optional.empty();
    }
}
