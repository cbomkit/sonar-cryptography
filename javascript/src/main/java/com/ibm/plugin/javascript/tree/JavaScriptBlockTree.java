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
package com.ibm.plugin.javascript.tree;

import java.util.List;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

/**
 * One top-level scope (the module body, or one function/method/arrow-function body) and the calls
 * made in it, in source order.
 *
 * <p>As in the C# converter, nested control-flow blocks are flattened into the enclosing block so
 * that a variable can be tracked across {@code if}/{@code for}/{@code try} boundaries.
 */
public final class JavaScriptBlockTree implements JavaScriptTree {

    private final int line;
    private final int column;
    @Nonnull private final List<JavaScriptTree> statements;
    @Nullable private final JavaScriptScope scope;

    public JavaScriptBlockTree(
            int line,
            int column,
            @Nonnull List<JavaScriptTree> statements,
            @Nullable JavaScriptScope scope) {
        this.line = line;
        this.column = column;
        this.statements = statements;
        this.scope = scope;
        for (JavaScriptTree statement : statements) {
            if (statement instanceof JavaScriptCallTree call) {
                call.setEnclosingBlock(this);
            }
        }
    }

    @Override
    public int getLine() {
        return line;
    }

    @Override
    public int getColumn() {
        return column;
    }

    @Nonnull
    @Override
    public String getText() {
        return "<block>";
    }

    @Nullable @Override
    public JavaScriptScope getScope() {
        return scope;
    }

    @Nonnull
    public List<JavaScriptTree> getStatements() {
        return statements;
    }
}
