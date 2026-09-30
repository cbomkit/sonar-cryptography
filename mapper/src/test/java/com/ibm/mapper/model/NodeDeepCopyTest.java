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
package com.ibm.mapper.model;

import static com.ibm.mapper.model.ModelNodes.TEST;
import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.mapper.model.algorithms.AES;
import com.ibm.mapper.model.collections.IAssetCollection;
import java.io.IOException;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;

/**
 * A copy of a node is a node of the same class, with a copy of each of its children: the class of a
 * node gives its composed name (e.g. {@code AES-256-CBC}), the OID the enrichers give it and the
 * way the output reports it. Every concrete node class of the model is checked.
 */
class NodeDeepCopyTest {

    @Test
    void everyNodeClassIsCopiedAsItself() throws IOException, URISyntaxException {
        final List<Class<? extends INode>> nodeClasses = ModelNodes.concreteNodeClasses();
        assertThat(nodeClasses).contains(AES.class, Mode.class, PrivateKey.class);

        final List<String> failures = new ArrayList<>();
        for (Class<? extends INode> nodeClass : nodeClasses) {
            final INode node = ModelNodes.build(nodeClass);
            node.put(new Oid("1.2.3", TEST));
            failures.addAll(differencesOfCopy(node));
        }
        assertThat(failures).isEmpty();
    }

    @Test
    void theOriginIsKept() {
        final Algorithm enriched =
                new Algorithm("TEST", BlockCipher.class, TEST, NodeOrigin.ENRICHED);
        assertThat(enriched.deepCopy().getOrigin()).isEqualTo(NodeOrigin.ENRICHED);

        final KeyLength keyLength = new KeyLength(128, TEST, NodeOrigin.ENRICHED);
        assertThat(keyLength.deepCopy().getOrigin()).isEqualTo(NodeOrigin.ENRICHED);
    }

    /** What differs between the node and its copy, other than being another object. */
    @Nonnull
    private static List<String> differencesOfCopy(@Nonnull INode node) {
        final String name = node.getClass().getName();
        final INode copy = node.deepCopy();
        final List<String> differences = new ArrayList<>();
        if (copy == node) {
            differences.add(name + ": the copy is the node itself");
        }
        if (copy.getClass() != node.getClass()) {
            differences.add(name + ": copied as " + copy.getClass().getName());
            return differences;
        }
        if (!copy.getKind().equals(node.getKind())) {
            differences.add(name + ": kind " + copy.getKind() + " instead of " + node.getKind());
        }
        if (!copy.asString().equals(node.asString())) {
            differences.add(name + ": named " + copy.asString() + " instead of " + node.asString());
        }
        if (copy.getOrigin() != node.getOrigin()) {
            differences.add(
                    name + ": origin " + copy.getOrigin() + " instead of " + node.getOrigin());
        }
        node.getChildren()
                .forEach(
                        (kind, child) -> {
                            final INode copiedChild = copy.getChildren().get(kind);
                            if (copiedChild == null) {
                                differences.add(name + ": child " + kind.getSimpleName() + " lost");
                            } else if (copiedChild == child) {
                                differences.add(
                                        name + ": child " + kind.getSimpleName() + " not copied");
                            } else if (copiedChild.getClass() != child.getClass()) {
                                differences.add(
                                        name
                                                + ": child "
                                                + kind.getSimpleName()
                                                + " copied as "
                                                + copiedChild.getClass().getName());
                            }
                        });
        final INode oid = node.getChildren().get(Oid.class);
        copy.removeChildOfType(Oid.class);
        if (node.getChildren().get(Oid.class) != oid) {
            differences.add(name + ": the copy shares the children of the node");
        }
        if (node instanceof IAssetCollection<?> collection
                && copy instanceof IAssetCollection<?> copiedCollection) {
            final List<?> items = collection.getCollection();
            final List<?> copiedItems = copiedCollection.getCollection();
            for (int i = 0; i < items.size(); i++) {
                if (copiedItems.get(i) == items.get(i)
                        || copiedItems.get(i).getClass() != items.get(i).getClass()) {
                    differences.add(name + ": item " + i + " not copied as itself");
                }
            }
        }
        return differences;
    }
}
