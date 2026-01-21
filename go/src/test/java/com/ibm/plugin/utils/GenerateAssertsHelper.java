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
package com.ibm.plugin.utils;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.language.go.GoScanContext;
import com.ibm.engine.model.IValue;
import com.ibm.mapper.model.INode;
import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sonar.go.symbols.Symbol;
import org.sonar.plugins.go.api.Tree;
import org.sonar.plugins.go.api.checks.GoCheck;

public class GenerateAssertsHelper {
    private static final Logger LOGGER = LoggerFactory.getLogger(GenerateAssertsHelper.class);

    private static final String FILE_PATH = "target/generated-asserts/";
    private static final String FILE_NAME = "asserts.txt";

    private static final String INITIAL_DETECTION_STORE_VARIABLE_NAME = "detectionStore";
    private static final String INITIAL_TRANSLATION_NODES_VARIABLE_NAME = "nodes";

    /**
     * Call this function inside the {@code asserts} function of a test. It will assume that the
     * input trees correspond to the ground truth of the detection store and translation. Therefore,
     * it will generate the code of all the assertions to verify that they match this ground truth.
     * The code of the assertions is added to your clipboard so you can paste them in your test file
     * (they are also stored in a temporary file in {@code target}).
     *
     * @param detectionStore - The root node of the tree of detection stores
     * @param translationRoots - The list of root nodes of translation trees
     */
    public static void generate(
            @Nonnull DetectionStore<GoCheck, Tree, Symbol, GoScanContext> detectionStore,
            @Nonnull List<INode> translationRoots) {
        // Create a directory if they do not yet exist
        try {
            Files.createDirectories(Paths.get(FILE_PATH));
        } catch (IOException e) {
            e.printStackTrace();
            return;
        }

        // Write the asserting
        try (FileWriter writer = new FileWriter(FILE_PATH + FILE_NAME)) {
            writer.write(
                    """
                    /*
                    * Detection Store
                    */
                    """);
            generateDetectionStoreAssertions(
                    writer, detectionStore, INITIAL_DETECTION_STORE_VARIABLE_NAME);

            writer.write(
                    """
                    /*
                    * Translation
                    */
                    """);
            generateNodeAssertions(
                    writer, translationRoots, INITIAL_TRANSLATION_NODES_VARIABLE_NAME);
        } catch (IOException e) {
            e.printStackTrace();
        }

        if (!GraphicsEnvironment.isHeadless()) {
            // Copy the resulting content to the clipboard
            try {
                copyFileToClipboard();
                LOGGER.debug("File content copied to clipboard successfully!");
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    private static void generateDetectionStoreAssertions(
            @Nonnull FileWriter writer,
            @Nonnull DetectionStore<GoCheck, Tree, Symbol, GoScanContext> detectionStore,
            @Nonnull String detectionStoreVarName)
            throws IOException {
        writer.write(String.format("assertThat(%s).isNotNull();%n", detectionStoreVarName));
        writer.write(
                String.format(
                        "assertThat(%s.getDetectionValues()).hasSize(%d);%n",
                        detectionStoreVarName, detectionStore.getDetectionValues().size()));
        writer.write(
                String.format(
                        "assertThat(%s.getDetectionValueContext()).isInstanceOf(%s.class);%n",
                        detectionStoreVarName,
                        detectionStore.getDetectionValueContext().getClass().getSimpleName()));

        for (int i = 0; i < detectionStore.getDetectionValues().size(); i++) {
            IValue<Tree> value = detectionStore.getDetectionValues().get(i);

            String valueNameStart = String.format("value%d", i);
            String valueVarName;

            if (detectionStoreVarName.equals(INITIAL_DETECTION_STORE_VARIABLE_NAME)) {
                valueVarName = valueNameStart;
            } else {
                valueVarName = detectionStoreVarName.replace("store", valueNameStart);
            }

            writer.write(
                    String.format(
                            "IValue<Tree> %s = %s.getDetectionValues().get(%d);%n",
                            valueVarName, detectionStoreVarName, i));
            writer.write(
                    String.format(
                            "assertThat(%s).isInstanceOf(%s.class);%n",
                            valueVarName, value.getClass().getSimpleName()));
            writer.write(
                    String.format(
                            "assertThat(%s.asString()).isEqualTo(\"%s\");%n",
                            valueVarName, value.asString()));
            writer.write("\n");
        }

        List<DetectionStore<GoCheck, Tree, Symbol, GoScanContext>> nonEmptyChildrenStores =
                detectionStore.getChildren().stream()
                        .filter(store -> !store.getDetectionValues().isEmpty())
                        .toList();

        int index = 1;
        for (DetectionStore<GoCheck, Tree, Symbol, GoScanContext> store : nonEmptyChildrenStores) {

            String childrenStoreVarName;
            if (detectionStoreVarName.equals(INITIAL_DETECTION_STORE_VARIABLE_NAME)) {
                childrenStoreVarName = String.format("%s%d", "store", index);
            } else {
                childrenStoreVarName = String.format("%s%d", detectionStoreVarName, index);
            }

            if (store.getDetectionValues().isEmpty()) {
                continue;
            }
            String kind = store.getDetectionValues().get(0).getClass().getSimpleName();

            writer.write(
                    String.format(
                            "DetectionStore<GoCheck, Tree, Symbol, GoScanContext> %s = getStoreOfValueType(%s.class, %s.getChildren());%n",
                            childrenStoreVarName, kind, detectionStoreVarName));

            generateDetectionStoreAssertions(writer, store, childrenStoreVarName);

            index++;
        }
    }

    private static void generateNodeAssertions(
            @Nonnull FileWriter writer, @Nonnull List<INode> nodes, @Nonnull String nodeVarName)
            throws IOException {
        writer.write(String.format("assertThat(%s).hasSize(%d);%n%n", nodeVarName, nodes.size()));

        for (int i = 0; i < nodes.size(); i++) {
            INode node = nodes.get(i);
            generateNodeAssertionsRecursive(writer, node, nodeVarName, i, null);
        }
    }

    private static final Map<String, Integer> usedKindNames = new HashMap<>();

    private static void generateNodeAssertionsRecursive(
            @Nonnull FileWriter writer,
            @Nonnull INode node,
            @Nonnull String previousNodeVarName,
            int index,
            @Nullable String previousTitle)
            throws IOException {

        String kindName = node.getKind().getSimpleName();

        usedKindNames.computeIfPresent(kindName, (key, value) -> value + 1);
        usedKindNames.computeIfAbsent(kindName, key -> 0);

        String number =
                usedKindNames.get(kindName) > 0
                        ? Integer.toString(usedKindNames.get(kindName))
                        : "";
        String nodeVarName =
                Character.toLowerCase(kindName.charAt(0)) + kindName.substring(1) + "Node" + number;

        if (kindName.equals("Algorithm")) {
            // Remove the confusion between the engine's and the mapper's Algorithm
            kindName = node.getKind().getName();
        }

        String title;
        if (index >= 0) {
            // Case of top level translation nodes
            title = kindName;
            writer.write(String.format("\t// %s%n", title));
            writer.write(
                    String.format(
                            "INode %s = %s.get(%d);%n", nodeVarName, previousNodeVarName, index));
            writer.write(
                    String.format(
                            "assertThat(%s.getKind()).isEqualTo(%s.class);%n",
                            nodeVarName, kindName));
        } else {
            // Case of children nodes
            title = String.format("%s under %s", kindName, previousTitle);
            writer.write(String.format("\t// %s%n", title));
            writer.write(
                    String.format(
                            "INode %s = %s.getChildren().get(%s.class);%n",
                            nodeVarName, previousNodeVarName, kindName));
            writer.write(String.format("assertThat(%s).isNotNull();%n", nodeVarName));
        }

        if (!node.getChildren().isEmpty()) {
            writer.write(
                    String.format(
                            "assertThat(%s.getChildren()).hasSize(%d);%n",
                            nodeVarName, node.getChildren().size()));
        } else {
            writer.write(String.format("assertThat(%s.getChildren()).isEmpty();%n", nodeVarName));
        }

        writer.write(
                String.format(
                        "assertThat(%s.asString()).isEqualTo(\"%s\");%n",
                        nodeVarName, node.asString()));
        writer.write("\n");

        for (Map.Entry<Class<? extends INode>, INode> child : node.getChildren().entrySet()) {
            generateNodeAssertionsRecursive(writer, child.getValue(), nodeVarName, -1, title);
        }
    }

    private static void copyFileToClipboard() throws IOException {
        // Read the file content
        String fileContent = Files.readString(Paths.get(FILE_PATH, FILE_NAME));
        // Copy the content to the system clipboard
        StringSelection stringSelection = new StringSelection(fileContent);
        Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
        clipboard.setContents(stringSelection, null);
    }
}
