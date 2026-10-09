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

import com.ibm.mapper.model.Algorithm;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.IPrimitive;
import com.ibm.mapper.utils.Function3;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

/**
 * This class contains public static {@code Function3} implementing usual reorganization actions,
 * that can be called from other reorganizer files.
 */
public final class UsualPerformActions {

    private UsualPerformActions() {
        // nothing
    }

    /**
     * When the current node is not a root node, this action will take all the node children and
     * move them to the same level (i.e., under the node's parent)
     */
    @Nonnull
    public static final IFunctionPerformReorganization performMovingChildrenUp =
            (node, parent, roots) -> {
                if (parent == null) {
                    // Do nothing
                    return roots;
                }
                final List<Class<? extends INode>> toRemove = new ArrayList<>();
                for (Map.Entry<Class<? extends INode>, INode> entry :
                        node.getChildren().entrySet()) {
                    Class<? extends INode> kind = entry.getKey();
                    INode child = entry.getValue();
                    // Append the child to `parent` and remove it from `node`
                    parent.put(child);
                    toRemove.add(kind);
                }
                for (Class<? extends INode> kind : toRemove) {
                    node.removeChildOfType(kind);
                }
                return roots;
            };

    /**
     * When there is a parent node and a child node of the same {@code kind}, this action will merge
     * both. In detail, it will put all the children nodes of the parent as children of the child
     * node, and will replace the parent node by the child node in the tree of nodes.
     *
     * @param kind - The kind of the parent and child nodes
     * @return A reorganization action (a {@code Function3})
     */
    @Nonnull
    public static IFunctionPerformReorganization performMergeParentAndChildOfSameKind(
            Class<? extends IPrimitive> kind) {
        return (node, parent, roots) -> {
            Algorithm newKindNode = (Algorithm) node.getChildren().get(kind);

            for (Map.Entry<Class<? extends INode>, INode> childKeyValue :
                    node.getChildren().entrySet()) {
                if (!childKeyValue.getKey().equals(kind)) {
                    newKindNode.put(childKeyValue.getValue());
                }
            }

            if (parent == null) {
                // `node` is a root node
                // Create a copy of the roots list
                List<INode> rootsCopy = new ArrayList<>(roots);
                for (int i = 0; i < rootsCopy.size(); i++) {
                    if (rootsCopy.get(i) == node) {
                        rootsCopy.set(i, newKindNode);
                        break;
                    }
                }
                return rootsCopy;
            } else {
                // Replace the previous `kind` node
                parent.put(newKindNode);
                return roots;
            }
        };
    }

    /**
     * Merges the child of the given kind of a node into the node: the node keeps its name and takes
     * the children of the child it does not have, e.g. the key length of the key set up for a
     * cipher operation.
     *
     * @param kind - The kind of the node and of its child
     * @return The {@code Function3} returning the updated list of root nodes
     */
    @Nonnull
    public static IFunctionPerformReorganization performMergeChildIntoParentOfSameKind(
            Class<? extends IPrimitive> kind) {
        return (node, parent, roots) -> {
            final INode child = node.getChildren().get(kind);
            node.removeChildOfType(kind);
            for (INode grandChild : child.getChildren().values()) {
                if (!node.getChildren().containsKey(grandChild.getKind())) {
                    node.put(grandChild);
                }
            }
            return roots;
        };
    }

    /**
     * This action is a helper function to replace a node: provide a {@code Function3} that returns
     * an updated node, and this action will replace the original node by this updated node.
     * Typically, it is useful to rename a node.
     *
     * @param perform - The {@code Function3} returning the updated node
     * @return The {@code Function3} returning the updated list of root nodes
     */
    @Nonnull
    public static IFunctionPerformReorganization performReplacingNode(
            @Nonnull Function3<INode, INode, List<INode>, INode> perform) {
        return (node, parent, roots) -> {
            INode newNode = perform.apply(node, parent, roots);
            return replaceNode(newNode, node, parent, roots);
        };
    }

    @Nonnull
    private static List<INode> replaceNode(
            @Nonnull INode newNode,
            @Nonnull INode originalNode,
            @Nullable INode parent,
            @Nonnull List<INode> roots) {
        // Add all the children to the new node
        for (Map.Entry<Class<? extends INode>, INode> childKeyValue :
                originalNode.getChildren().entrySet()) {
            newNode.put(childKeyValue.getValue());
        }
        if (parent == null) {
            // `node` is a root node
            // Create a copy of the root nodes
            List<INode> rootsCopy = new ArrayList<>(roots);
            for (int i = 0; i < rootsCopy.size(); i++) {
                if (rootsCopy.get(i) == originalNode) {
                    rootsCopy.set(i, newNode);
                    break;
                }
            }
            return rootsCopy;
        } else {
            // Replace the previous node
            parent.put(newNode);
            return roots;
        }
    }
}
