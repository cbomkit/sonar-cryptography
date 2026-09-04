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
import com.ibm.mapper.model.INode;
import com.ibm.output.IAggregator;
import com.ibm.plugin.javascript.api.JavaScriptCheck;
import com.ibm.plugin.javascript.api.JavaScriptSymbol;
import com.ibm.plugin.javascript.api.Tree;
import com.ibm.plugin.javascript.language.JavaScriptLanguageSupport;
import com.ibm.plugin.javascript.language.JavaScriptScanContext;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import javax.annotation.Nonnull;

public final class JavaScriptAggregator implements IAggregator {

    private static ILanguageSupport<JavaScriptCheck, Tree, JavaScriptSymbol, JavaScriptScanContext>
            javascriptLanguageSupport = new JavaScriptLanguageSupport();

    private static List<INode> detectedNodes = new ArrayList<>();

    private JavaScriptAggregator() {
        // utility
    }

    @Nonnull
    public static ILanguageSupport<JavaScriptCheck, Tree, JavaScriptSymbol, JavaScriptScanContext>
            getLanguageSupport() {
        return javascriptLanguageSupport;
    }

    @Nonnull
    public static List<INode> getDetectedNodes() {
        return Collections.unmodifiableList(detectedNodes);
    }

    public static void addNodes(@Nonnull List<INode> newNodes) {
        if (newNodes.isEmpty()) {
            return;
        }
        detectedNodes.addAll(newNodes);
        IAggregator.log(newNodes);
    }

    public static void reset() {
        javascriptLanguageSupport = new JavaScriptLanguageSupport();
        detectedNodes = new ArrayList<>();
    }
}
