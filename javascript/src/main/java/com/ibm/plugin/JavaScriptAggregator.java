/*
 * Sonar Cryptography Plugin
 * Copyright (C) 2026 PQCA
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
import com.ibm.mapper.model.INode;
import com.ibm.output.IAggregator;
import com.ibm.plugin.javascript.language.JavaScriptCheck;
import com.ibm.plugin.javascript.language.JavaScriptLanguageSupport;
import com.ibm.plugin.javascript.language.JavaScriptScanContext;
import com.ibm.plugin.javascript.language.JavaScriptSymbol;
import com.ibm.plugin.javascript.tree.JavaScriptTree;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import javax.annotation.Nonnull;

/** Static accumulator for JavaScript/TypeScript cryptographic detection results. */
public final class JavaScriptAggregator implements IAggregator {

    private static ILanguageSupport<
                    JavaScriptCheck, JavaScriptTree, JavaScriptSymbol, JavaScriptScanContext>
            javascriptLanguageSupport = new JavaScriptLanguageSupport();

    private static List<INode> detectedNodes = new ArrayList<>();

    private JavaScriptAggregator() {
        // nothing
    }

    @Nonnull
    public static ILanguageSupport<
                    JavaScriptCheck, JavaScriptTree, JavaScriptSymbol, JavaScriptScanContext>
            getLanguageSupport() {
        return javascriptLanguageSupport;
    }

    @Nonnull
    public static List<INode> getDetectedNodes() {
        return Collections.unmodifiableList(detectedNodes);
    }

    public static void addNodes(@Nonnull List<INode> newNodes) {
        detectedNodes.addAll(newNodes);
        IAggregator.log(newNodes);
    }

    public static void reset() {
        javascriptLanguageSupport = new JavaScriptLanguageSupport();
        detectedNodes = new ArrayList<>();
    }
}
