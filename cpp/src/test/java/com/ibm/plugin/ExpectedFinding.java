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
package com.ibm.plugin;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.model.IValue;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.collections.IAssetCollection;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import javax.annotation.Nonnull;
import org.assertj.core.api.Assertions;

/**
 * The expected detection store and translation of a finding, by finding id, as the detection rule
 * tests of the Java module assert them: the store with its context, its values and the stores with
 * values below it, and the translated nodes with all their children.
 *
 * <p>A store is described as {@code Context{ValueType:value, ...}[child, ...]}, keeping only the
 * stores that hold a value or have one below them. A node is described as {@code Kind:name[child,
 * ...]}, the children sorted, and a collection as {@code Kind:[item, ...]}.
 *
 * <p>Running a test with {@code -Dcpp.printFindings=true} prints its findings in this form, as the
 * entries of the table the test declares.
 */
public record ExpectedFinding(@Nonnull String store, @Nonnull List<String> nodes) {

    private static final boolean PRINT = Boolean.getBoolean("cpp.printFindings");

    @Nonnull
    public static ExpectedFinding finding(@Nonnull String store, @Nonnull String... nodes) {
        return new ExpectedFinding(store, List.of(nodes));
    }

    /** Asserts the finding {@code findingId} against the expected findings, in their order. */
    public static void assertFinding(
            @Nonnull List<ExpectedFinding> expected,
            int findingId,
            @Nonnull DetectionStore<?, ?, ?, ?> detectionStore,
            @Nonnull List<INode> nodes) {
        if (PRINT) {
            return;
        }
        final String store = describe(detectionStore);
        final List<String> translation = nodes.stream().map(ExpectedFinding::describe).toList();
        assertThat(findingId)
                .as("finding %d is not expected", findingId)
                .isLessThan(expected.size());
        final ExpectedFinding finding = expected.get(findingId);
        assertThat(store).as("detection store of finding %d", findingId).isEqualTo(finding.store());
        assertThat(translation)
                .as("translation of finding %d", findingId)
                .containsExactlyElementsOf(finding.nodes());
    }

    /** Asserts that every expected finding was reported. */
    public static void assertAllReported(@Nonnull List<ExpectedFinding> expected, int findings) {
        if (!PRINT) {
            Assertions.assertThat(findings).as("findings").isEqualTo(expected.size());
        }
    }

    /** The store, its values and the stores with values below it. */
    @Nonnull
    public static String describe(@Nonnull DetectionStore<?, ?, ?, ?> store) {
        final String values =
                store.getDetectionValues().stream()
                        .map(ExpectedFinding::describe)
                        .collect(Collectors.joining(", "));
        final List<String> children = new ArrayList<>();
        for (DetectionStore<?, ?, ?, ?> child : store.getChildren()) {
            if (hasValue(child)) {
                children.add(describe(child));
            }
        }
        return store.getDetectionValueContext().getClass().getSimpleName()
                + "{"
                + values
                + "}"
                + (children.isEmpty() ? "" : "[" + String.join(", ", children) + "]");
    }

    /** The node, and all its children sorted. */
    @Nonnull
    public static String describe(@Nonnull INode node) {
        final String self =
                node instanceof IAssetCollection<?> collection
                        ? node.getKind().getSimpleName()
                                + ":["
                                + collection.getCollection().stream()
                                        .map(item -> describe((INode) item))
                                        .collect(Collectors.joining(", "))
                                + "]"
                        : node.getKind().getSimpleName() + ":" + node.asString();
        final String children =
                node.getChildren().values().stream()
                        .map(ExpectedFinding::describe)
                        .sorted()
                        .collect(Collectors.joining(", "));
        return children.isEmpty() ? self : self + "[" + children + "]";
    }

    @Nonnull
    private static String describe(@Nonnull IValue<?> value) {
        return value.getClass().getSimpleName() + ":" + value.asString();
    }

    private static boolean hasValue(@Nonnull DetectionStore<?, ?, ?, ?> store) {
        return !store.getDetectionValues().isEmpty()
                || store.getChildren().stream().anyMatch(ExpectedFinding::hasValue);
    }

    /** Prints the finding as an entry of the expected findings, when requested. */
    static void printIfRequested(
            @Nonnull String test,
            int findingId,
            int line,
            @Nonnull DetectionStore<?, ?, ?, ?> detectionStore,
            @Nonnull List<INode> nodes) {
        if (!PRINT) {
            return;
        }
        final StringBuilder entry =
                new StringBuilder("FINDING ")
                        .append(test)
                        .append(' ')
                        .append(findingId)
                        .append(' ')
                        .append(line)
                        .append(" finding(")
                        .append(literal(describe(detectionStore)));
        nodes.forEach(node -> entry.append(", ").append(literal(describe(node))));
        System.out.println(entry.append("),"));
    }

    @Nonnull
    private static String literal(@Nonnull String text) {
        return "\"" + text.replace("\\", "\\\\").replace("\"", "\\\"") + "\"";
    }
}
