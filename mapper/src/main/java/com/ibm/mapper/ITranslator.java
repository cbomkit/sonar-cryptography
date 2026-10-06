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
import com.ibm.engine.model.context.DetectionContext;
import com.ibm.engine.rule.IBundle;
import com.ibm.mapper.model.IAlgorithm;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.NodeOrigin;
import com.ibm.mapper.model.collections.AbstractAssetCollection;
import com.ibm.mapper.model.collections.IAssetCollection;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.IdentityHashMap;
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
                new Traverser<>(
                        rootDetectionStore,
                        this::translateStore,
                        argumentsConfigureTheOperatedObject());
        return traverser.translate();
    }

    @Nonnull
    private Map<Integer, List<INode>> translateStore(@Nonnull DetectionStore<R, T, S, P> store) {
        final String filePath = store.getScanContext().getRelativePath();
        final IBundle bundle = store.getDetectionRule().bundle();
        final DetectionContext context = store.getDetectionValueContext();

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
            @Nonnull DetectionContext detectionValueContext,
            @Nonnull final String filePath);

    @Nullable protected abstract DetectionLocation getDetectionContextFrom(
            @Nonnull T location, @Nonnull final IBundle bundle, @Nonnull String filePath);

    /**
     * Whether an argument of a call that has no node of its own configures the object the call
     * operates on. In C, a function operates on the object it is given, e.g. {@code
     * EVP_KDF_derive(ctx, out, 32, params)} sets the key length and the parameters of the key
     * derivation function of {@code ctx}. By default, such an argument adds to the first node of
     * the call, as the arguments of a method add to what the method sets up.
     */
    protected boolean argumentsConfigureTheOperatedObject() {
        return false;
    }

    /*
     * private traverser
     */
    static class Traverser<R, T, S, P> {
        @Nonnull final DetectionStore<R, T, S, P> rootDetectionStore;
        @Nonnull final List<Alternative> alternatives = new ArrayList<>();

        /** The nodes merged into an equal node they were appended to, see {@link #append}. */
        @Nonnull final Map<INode, INode> mergedNodes = new IdentityHashMap<>();

        @Nonnull final Function<DetectionStore<R, T, S, P>, Map<Integer, List<INode>>> translator;
        final boolean argumentsConfigureTheOperatedObject;

        public Traverser(
                @Nonnull DetectionStore<R, T, S, P> rootDetectionStore,
                @Nonnull Function<DetectionStore<R, T, S, P>, Map<Integer, List<INode>>> translator,
                boolean argumentsConfigureTheOperatedObject) {
            this.rootDetectionStore = rootDetectionStore;
            this.translator = translator;
            this.argumentsConfigureTheOperatedObject = argumentsConfigureTheOperatedObject;
        }

        @Nonnull
        public List<INode> translate() {
            final Map<Integer, List<INode>> rootNodes = translator.apply(rootDetectionStore);
            final List<Map<Integer, List<INode>>> uses;
            if (rootNodes.isEmpty()) {
                uses = traversUses(rootDetectionStore);
            } else {
                travers(rootDetectionStore, rootNodes, null);
                uses = List.of(rootNodes);
            }
            final List<INode> translatedRootNodes =
                    new ArrayList<>(
                            uses.stream()
                                    .flatMap(use -> use.values().stream())
                                    .flatMap(List::stream)
                                    .toList());
            translatedRootNodes.addAll(alternativeRoots(translatedRootNodes));
            return translatedRootNodes;
        }

        /**
         * Appends the nodes of the children of a store to the nodes of the store ({@code
         * parentNodes}), which were appended to {@code enclosingNodes}, or are roots when that is
         * null.
         */
        private void travers(
                @Nonnull DetectionStore<R, T, S, P> store,
                @Nonnull Map<Integer, List<INode>> parentNodes,
                @Nullable Map<Integer, List<INode>> enclosingNodes) {
            store.getChildrenForMethod()
                    .forEach(child -> translateAndAppend(-1, child, parentNodes, enclosingNodes));
            store.childrenForEachParameter(
                    (id, children) -> {
                        for (DetectionStore<R, T, S, P> child : children) {
                            translateAndAppend(id, child, parentNodes, enclosingNodes);
                        }
                    });
        }

        /**
         * The uses of an object created by a call without a node of its own, e.g. the creation of a
         * context by a C function, each with the nodes describing it. The arguments of the call
         * that created the object describe it, and the calls made on it add to that description. An
         * object created without describing arguments, e.g. by {@code EVP_CIPHER_CTX_new()}, gets
         * its algorithm from a call made on it: a call that brings another algorithm once the
         * object has one, e.g. the context initialized again with another cipher, starts another
         * use of the object, which the calls after it describe.
         */
        @Nonnull
        private List<Map<Integer, List<INode>>> traversUses(
                @Nonnull DetectionStore<R, T, S, P> store) {
            final Map<Integer, List<INode>> describedByArguments = new HashMap<>();
            store.childrenForEachParameter(
                    (id, children) -> {
                        for (DetectionStore<R, T, S, P> child : children) {
                            translateAndAppend(id, child, describedByArguments, null);
                        }
                    });
            final boolean usedAsCreated = !describedByArguments.isEmpty();
            final List<Map<Integer, List<INode>>> uses = new ArrayList<>();
            Map<Integer, List<INode>> use = describedByArguments;
            for (DetectionStore<R, T, S, P> child : store.getChildrenForMethod()) {
                if (!usedAsCreated && hasAlgorithm(use) && bringsAlgorithm(child)) {
                    uses.add(use);
                    use = new HashMap<>();
                }
                translateAndAppend(-1, child, use, null);
            }
            uses.add(use);
            return uses;
        }

        /**
         * Whether the nodes of a call made on an object, and of the calls below it, hold an
         * algorithm.
         */
        private boolean bringsAlgorithm(@Nonnull DetectionStore<R, T, S, P> call) {
            // translated on its own, so that its values do not count as other values of this tree
            final Map<Integer, List<INode>> nodes = new HashMap<>();
            new Traverser<>(call, translator, argumentsConfigureTheOperatedObject)
                    .translateAndAppend(-1, call, nodes, null);
            return hasAlgorithm(nodes);
        }

        private static boolean hasAlgorithm(@Nonnull Map<Integer, List<INode>> nodes) {
            return nodes.values().stream().flatMap(List::stream).anyMatch(Traverser::hasAlgorithm);
        }

        private static boolean hasAlgorithm(@Nonnull INode node) {
            if (node instanceof IAlgorithm) {
                return true;
            }
            if (node instanceof IAssetCollection<?> collection
                    && collection.getCollection().stream().anyMatch(Traverser::hasAlgorithm)) {
                return true;
            }
            return node.getChildren().values().stream().anyMatch(Traverser::hasAlgorithm);
        }

        private void translateAndAppend(
                int id,
                @Nonnull DetectionStore<R, T, S, P> child,
                @Nonnull Map<Integer, List<INode>> mapOfParentNodes,
                @Nullable Map<Integer, List<INode>> enclosingNodes) {

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
                                        this.append(
                                                nodesConfiguredBy(mapOfParentNodes, enclosingNodes),
                                                newNodesCollection);
                                    }
                                });
            }

            // next iteration
            if (nodes.isEmpty()) {
                travers(child, mapOfParentNodes, enclosingNodes);
            } else {
                travers(child, withMergedNodes(nodes), mapOfParentNodes);
            }
        }

        /**
         * The nodes, each merged node replaced by the node it was merged into, so that what is
         * found below a node adds to the node that holds its value.
         */
        @Nonnull
        private Map<Integer, List<INode>> withMergedNodes(
                @Nonnull Map<Integer, List<INode>> nodes) {
            final Map<Integer, List<INode>> result = new HashMap<>();
            nodes.forEach(
                    (id, list) ->
                            result.put(
                                    id,
                                    new ArrayList<>(
                                            list.stream()
                                                    .map(
                                                            node ->
                                                                    mergedNodes.getOrDefault(
                                                                            node, node))
                                                    .toList())));
            return result;
        }

        /**
         * The nodes that an argument of a call configures when the call has no node for that
         * argument: the first nodes of the call, or, where arguments configure the operated object
         * (see {@link ITranslator#argumentsConfigureTheOperatedObject()}), the operation of the
         * call, else what the nodes of the call describe, e.g. the key derivation function whose
         * key length and parameters {@code EVP_KDF_derive(ctx, out, 32, params)} sets.
         */
        @Nonnull
        private List<INode> nodesConfiguredBy(
                @Nonnull Map<Integer, List<INode>> callNodes,
                @Nullable Map<Integer, List<INode>> enclosingNodes) {
            if (!argumentsConfigureTheOperatedObject) {
                return callNodes.values().iterator().next();
            }
            if (callNodes.containsKey(-1)) {
                return callNodes.get(-1);
            }
            if (enclosingNodes != null && !enclosingNodes.isEmpty()) {
                return enclosingNodes.getOrDefault(-1, enclosingNodes.values().iterator().next());
            }
            return callNodes.values().iterator().next();
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
                                /* Special case of multiple mergeable asset collections of the same type: we merge them */
                                if (childNode
                                                instanceof
                                                AbstractAssetCollection<?> addedCollectionNode
                                        && existingNode
                                                instanceof
                                                AbstractAssetCollection<?> existingCollectionNode
                                        && addedCollectionNode.isMergeable()
                                        /* this condition ensures that both nodes have the same *exact* class */
                                        && addedCollectionNode
                                                .getClass()
                                                .equals(existingCollectionNode.getClass())) {

                                    @SuppressWarnings("unchecked")
                                    AbstractAssetCollection<INode> existingColl =
                                            (AbstractAssetCollection<INode>) existingCollectionNode;
                                    @SuppressWarnings("unchecked")
                                    AbstractAssetCollection<INode> addedColl =
                                            (AbstractAssetCollection<INode>) addedCollectionNode;

                                    List<INode> mergedCollection =
                                            new ArrayList<>(existingColl.getCollection());
                                    mergedCollection.addAll(addedColl.getCollection());

                                    AbstractAssetCollection<INode> mergedCollectionNode =
                                            existingColl.createMerged(mergedCollection);

                                    addedColl
                                            .getChildren()
                                            .values()
                                            .forEach(mergedCollectionNode::put);
                                    existingColl
                                            .getChildren()
                                            .values()
                                            .forEach(mergedCollectionNode::put);

                                    parentNode.put(mergedCollectionNode);
                                } else if (existingNode.is(childNode.getKind())
                                        && existingNode.asString().equals(childNode.asString())) {
                                    // the same value again: what is found with it and below it
                                    // adds to it, e.g. the salt length set for an RSA-PSS
                                    // signature
                                    if (existingNode != childNode) {
                                        this.append(
                                                List.of(existingNode),
                                                List.copyOf(childNode.getChildren().values()));
                                        mergedNodes.putIfAbsent(childNode, existingNode);
                                    }
                                } else if (existingNode.is(childNode.getKind())) {
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
                                        // Both are DETECTED with different values: another tree
                                        // with this value, built once the tree is complete
                                        alternatives.add(new Alternative(parentNode, childNode));
                                    }
                                }
                            } else {
                                parentNode.put(childNode);
                            }
                        });
            }
        }

        /**
         * A tree for each other value found for a node that already has a value of that kind, e.g.
         * the second key length of a key set up twice: a copy of the complete tree of the node, in
         * which the other value takes the place of the value of the node. The trees are built once
         * the traversal is complete, so that they hold everything found in the tree and below the
         * value, and they share no node with it. A node that is in no tree gets a copy of itself
         * with the other value.
         */
        @Nonnull
        private List<INode> alternativeRoots(@Nonnull List<INode> roots) {
            final List<INode> searched = new ArrayList<>(roots);
            final List<INode> alternativeRoots = new ArrayList<>();
            for (Alternative alternative : alternatives) {
                final INode alternativeRoot =
                        searched.stream()
                                .map(
                                        root ->
                                                pathTo(root, alternative.node())
                                                        .map(
                                                                path ->
                                                                        copyWith(
                                                                                root,
                                                                                path,
                                                                                alternative
                                                                                        .value())))
                                .flatMap(Optional::stream)
                                .findFirst()
                                .orElseGet(
                                        () ->
                                                copyWith(
                                                        alternative.node(),
                                                        List.of(),
                                                        alternative.value()));
                alternativeRoots.add(alternativeRoot);
                searched.add(alternativeRoot);
            }
            return alternativeRoots;
        }

        /** A copy of the root with a copy of the value put in the node at the end of the path. */
        @Nonnull
        private static INode copyWith(
                @Nonnull INode root, @Nonnull List<Step> path, @Nonnull INode value) {
            final INode copy = root.deepCopy();
            INode node = copy;
            for (Step step : path) {
                node = step.from(node);
            }
            node.put(value.deepCopy());
            return copy;
        }

        /** The steps from the node to the target, when the target is the node or below it. */
        @Nonnull
        private static Optional<List<Step>> pathTo(@Nonnull INode node, @Nonnull INode target) {
            if (node == target) {
                return Optional.of(new ArrayList<>());
            }
            for (Map.Entry<Class<? extends INode>, INode> child : node.getChildren().entrySet()) {
                final Optional<List<Step>> below = pathTo(child.getValue(), target);
                if (below.isPresent()) {
                    below.get().add(0, Step.child(child.getKey()));
                    return below;
                }
            }
            if (node instanceof IAssetCollection<?> collection) {
                final List<? extends INode> items = collection.getCollection();
                for (int i = 0; i < items.size(); i++) {
                    final Optional<List<Step>> below = pathTo(items.get(i), target);
                    if (below.isPresent()) {
                        below.get().add(0, Step.item(i));
                        return below;
                    }
                }
            }
            return Optional.empty();
        }

        /** Another value of the kind of a value the node already has. */
        private record Alternative(@Nonnull INode node, @Nonnull INode value) {}

        /**
         * A step from a node to its child of a kind, or to the item at an index of its collection.
         */
        private record Step(@Nullable Class<? extends INode> kind, int item) {

            @Nonnull
            static Step child(@Nonnull Class<? extends INode> kind) {
                return new Step(kind, -1);
            }

            @Nonnull
            static Step item(int item) {
                return new Step(null, item);
            }

            @Nonnull
            INode from(@Nonnull INode node) {
                if (kind != null) {
                    return node.getChildren().get(kind);
                }
                return ((IAssetCollection<?>) node).getCollection().get(item);
            }
        }
    }
}
