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
package com.ibm.mapper;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.context.IDetectionContext;
import com.ibm.engine.rule.IBundle;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.NodeOrigin;
import com.ibm.mapper.model.collections.MergeableCollection;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public abstract class ITranslator<R, T, S, P> {

    public static final String UNKNOWN = "unknown";

    /**
     * The translation method is responsible for translating the provided detection store. It
     * performs several important tasks within its implementation: <br>
     * retrieve the detection values, and for each value, a new issue is reported using the provided
     * rule, location, and string representation.
     * <li>Retrieves the file path of the root detection store. This allows the method to identify
     *     and retrieve the assets associated with the root detection values.
     * <li>Translates the detection values into asset values using the provided rootDetectionStore.
     *     The resulting assets are stored in a new List<INode> called rootAssetValues.
     * <li>Handles any child detection stores by recursively traversing the detection store
     *     hierarchy. This ensures that all relevant assets are accounted for during the translation
     *     process.
     * <li>Prints the node tree based on the translated detection values. This allows developers to
     *     visualize the structure and relationships between different nodes in the system.
     * <li>Finally, returns the rootAssetValues list as the output of the method. This allows other
     *     parts of the program to use the translated detection values for further processing or
     *     analysis. <br>
     */
    @Nonnull
    public List<INode> translate(@Nonnull DetectionStore<R, T, S, P> rootDetectionStore) {
        final Traverser<R, T, S, P> traverser =
                new Traverser<>(rootDetectionStore, this::translateStore);
        return traverser.translate();
    }

    @Nonnull
    private Map<Integer, List<INode>> translateStore(@Nonnull DetectionStore<R, T, S, P> store) {
        final String filePath = store.getScanContext().getRelativePath();
        final IBundle bundle = store.getDetectionRule().bundle();
        final IDetectionContext context = store.getDetectionValueContext();

        final Map<Integer, List<INode>> nodes = new HashMap<>();
        store.getActionValue()
                .ifPresent(
                        actionValue -> {
                            final Optional<INode> translatedNode =
                                    this.translate(bundle, actionValue, context, filePath);
                            translatedNode.ifPresent(
                                    node -> {
                                        final List<INode> newNodes = new ArrayList<>();
                                        newNodes.add(node);
                                        nodes.put(-1, newNodes);
                                    });
                        });
        store.detectionValuesForEachParameter(
                (id, values) -> {
                    final List<INode> translatedNodesForId = new ArrayList<>();
                    for (IValue<T> value : values) {
                        final Optional<INode> translatedNode =
                                this.translate(bundle, value, context, filePath);
                        translatedNode.ifPresent(translatedNodesForId::add);
                    }
                    // to get the list for the key, or create a new one if it doesn't exist and add
                    // additional nodes
                    nodes.computeIfAbsent(id, n -> new ArrayList<>()).addAll(translatedNodesForId);
                });
        return nodes;
    }

    @Nonnull
    protected abstract Optional<INode> translate(
            @Nonnull final IBundle bundleIdentifier,
            @Nonnull IValue<T> value,
            @Nonnull IDetectionContext detectionValueContext,
            @Nonnull final String filePath);

    @Nullable protected abstract DetectionLocation getDetectionContextFrom(
            @Nonnull T location, @Nonnull final IBundle bundle, @Nonnull String filePath);

    /*
     * private traverser
     */
    static class Traverser<R, T, S, P> {
        @Nonnull final DetectionStore<R, T, S, P> rootDetectionStore;
        @Nonnull final List<INode> newRoots = new ArrayList<>();
        @Nonnull final Function<DetectionStore<R, T, S, P>, Map<Integer, List<INode>>> translator;

        public Traverser(
                @Nonnull DetectionStore<R, T, S, P> rootDetectionStore,
                @Nonnull
                        Function<DetectionStore<R, T, S, P>, Map<Integer, List<INode>>>
                                translator) {
            this.rootDetectionStore = rootDetectionStore;
            this.translator = translator;
        }

        @Nonnull
        public List<INode> translate() {
            final Map<Integer, List<INode>> rootNodes = translator.apply(rootDetectionStore);
            travers(rootDetectionStore, rootNodes);
            final List<INode> translatedRootNodes =
                    new ArrayList<>(rootNodes.values().stream().flatMap(List::stream).toList());
            translatedRootNodes.addAll(newRoots);
            return translatedRootNodes;
        }

        private void travers(
                @Nonnull DetectionStore<R, T, S, P> store,
                @Nonnull Map<Integer, List<INode>> parentNodes) {
            store.getChildrenForMethod()
                    .forEach(child -> translateAndAppend(-1, child, parentNodes));
            store.childrenForEachParameter(
                    (id, children) -> {
                        for (DetectionStore<R, T, S, P> child : children) {
                            translateAndAppend(id, child, parentNodes);
                        }
                    });
        }

        private void translateAndAppend(
                int id,
                @Nonnull DetectionStore<R, T, S, P> child,
                @Nonnull Map<Integer, List<INode>> mapOfParentNodes) {

            Map<Integer, List<INode>> nodes = translator.apply(child);
            // collect nodes and add to parent
            final List<INode> newNodesCollection =
                    nodes.values().stream().flatMap(List::stream).toList();

            if (!newNodesCollection.isEmpty()) {
                Optional.ofNullable(mapOfParentNodes.get(id))
                        .ifPresentOrElse(
                                parentNodes -> this.append(parentNodes, newNodesCollection),
                                () -> {
                                    // no parent node with related id
                                    if (mapOfParentNodes.isEmpty()) {
                                        mapOfParentNodes.put(
                                                -1, newNodesCollection); // add node as main
                                    } else {
                                        mapOfParentNodes.values().stream()
                                                .findFirst()
                                                .ifPresent(
                                                        parentNodes ->
                                                                this.append(
                                                                        parentNodes,
                                                                        newNodesCollection));
                                    }
                                });
            }

            if (nodes.isEmpty()) {
                nodes = mapOfParentNodes;
            }
            // next iteration
            travers(child, nodes);
        }

        private void append(
                @Nonnull List<INode> parentNodes, @Nonnull List<INode> newNodesCollection) {

            final List<INode> copyParentNodes = List.copyOf(parentNodes); // copy of references
            for (INode parentNode : copyParentNodes) {
                newNodesCollection.forEach(
                        childNode -> {
                            Optional<INode> existingNodeOpt =
                                    parentNode.hasChildOfType(childNode.getKind());
                            if (existingNodeOpt.isPresent()) {
                                INode existingNode = existingNodeOpt.get();
                                /* Special case of multiple `MergeableCollection`: we merge them */
                                if (childNode instanceof MergeableCollection addedCollectionNode
                                        && existingNode
                                                instanceof
                                                MergeableCollection existingCollectionNode
                                        /* this 3rd condition ensures that both nodes have the same *exact* class */
                                        && addedCollectionNode
                                                .getClass()
                                                .equals(existingCollectionNode.getClass())) {

                                    List<INode> mergedCollection =
                                            new ArrayList<>(existingCollectionNode.getCollection());
                                    mergedCollection.addAll(addedCollectionNode.getCollection());

                                    MergeableCollection mergedCollectionNode =
                                            new MergeableCollection(mergedCollection);

                                    addedCollectionNode
                                            .getChildren()
                                            .values()
                                            .forEach(mergedCollectionNode::put);
                                    existingCollectionNode
                                            .getChildren()
                                            .values()
                                            .forEach(mergedCollectionNode::put);

                                    parentNode.put(mergedCollectionNode);
                                } else if (existingNode.is(childNode.getKind())
                                        && !existingNode.asString().equals(childNode.asString())) {
                                    // Handle based on origin:
                                    // - DETECTED values override DEFAULT/ENRICHED values
                                    // - Only create new roots when both are DETECTED with different
                                    // values
                                    if (existingNode.getOrigin() == NodeOrigin.DEFAULT
                                            || existingNode.getOrigin() == NodeOrigin.ENRICHED) {
                                        // Replace default/enriched with detected value
                                        if (childNode.getOrigin() == NodeOrigin.DETECTED) {
                                            parentNode.put(childNode);
                                        }
                                        // If child is also DEFAULT/ENRICHED, keep existing
                                    } else if (childNode.getOrigin() == NodeOrigin.DEFAULT
                                            || childNode.getOrigin() == NodeOrigin.ENRICHED) {
                                        // Keep existing DETECTED value, ignore default/enriched
                                        // child
                                    } else {
                                        // Both are DETECTED with different values: create new roots
                                        final INode newParent = parentNode.deepCopy();
                                        newParent.put(childNode);
                                        newRoots.add(newParent);
                                    }
                                }
                            } else {
                                parentNode.put(childNode);
                            }
                        });
            }
        }
    }
}
