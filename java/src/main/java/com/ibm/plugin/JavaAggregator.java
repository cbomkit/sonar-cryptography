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

import com.ibm.engine.language.ILanguageSupport;
import com.ibm.engine.language.LanguageSupporter;
import com.ibm.mapper.model.INode;
import com.ibm.output.IAggregator;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import javax.annotation.Nonnull;
import org.sonar.plugins.java.api.JavaCheck;
import org.sonar.plugins.java.api.JavaFileScannerContext;
import org.sonar.plugins.java.api.semantic.Symbol;
import org.sonar.plugins.java.api.tree.Tree;

public final class JavaAggregator implements IAggregator {

    private static final int BATCH_SIZE = 1000;

    private static ILanguageSupport<JavaCheck, Tree, Symbol, JavaFileScannerContext>
            javaLanguageSupport = LanguageSupporter.javaLanguageSupporter();
    private static List<INode> detectedNodes = new ArrayList<>();

    private JavaAggregator() {
        // nothing
    }

    public static void addNodes(@Nonnull List<INode> newNodes) {
        detectedNodes.addAll(newNodes);
        IAggregator.log(newNodes);

        if (detectedNodes.size() >= BATCH_SIZE) {
            System.err.println(
                    "[MEMORY] Processed "
                            + detectedNodes.size()
                            + " findings. Peak memory will be lower.");
        }
    }

    @Nonnull
    public static List<INode> getDetectedNodes() {
        return Collections.unmodifiableList(detectedNodes);
    }

    @Nonnull
    public static ILanguageSupport<JavaCheck, Tree, Symbol, JavaFileScannerContext>
            getLanguageSupport() {
        return javaLanguageSupport;
    }

    public static void reset() {
        javaLanguageSupport = LanguageSupporter.javaLanguageSupporter();
        detectedNodes = new ArrayList<>();
    }

    public static void flush() {
        if (!detectedNodes.isEmpty()) {
            System.err.println("[MEMORY] Flushing remaining " + detectedNodes.size() + " findings");
        }
    }
}
