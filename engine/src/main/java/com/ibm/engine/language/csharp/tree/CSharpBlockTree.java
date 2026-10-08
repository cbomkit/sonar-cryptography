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
package com.ibm.engine.language.csharp.tree;

import java.util.List;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

/**
 * Represents a C# code block (method body, lambda, local function, etc.), containing a list of
 * statements.
 *
 * <p>This is the entry point for the detection engine — the sensor dispatches one block per
 * top-level scope (method/constructor/accessor/operator body, lambda body, local function body) to
 * the engine for crypto pattern detection. Nested control-flow blocks ({@code if}/{@code
 * for}/{@code while}/{@code using}/{@code try}/{@code catch}/{@code finally}/{@code checked}/{@code
 * unchecked}/{@code unsafe}) are <em>not</em> separate {@code CSharpBlockTree}s: {@code
 * CSharpTreeConverter} flattens their statements into the enclosing top-level block (in a nested
 * {@link CSharpScope}) so that variable tracking and depending detection rules work across
 * statement-block boundaries within the same method — see {@code CSharpTreeConverter}'s class
 * javadoc for the flattening rules.
 */
public final class CSharpBlockTree implements CSharpTree {

    private final int line;
    private final int column;
    @Nonnull private final List<CSharpTree> statements;
    @Nullable private final CSharpScope scope;

    public CSharpBlockTree(
            int line,
            int column,
            @Nonnull List<CSharpTree> statements,
            @Nullable CSharpScope scope) {
        this.line = line;
        this.column = column;
        this.statements = statements;
        this.scope = scope;
        // Back-patch each statement so getEnclosingMethod() can navigate back to this block
        for (CSharpTree statement : statements) {
            if (statement instanceof CSharpMethodInvocationTree inv) {
                inv.setEnclosingBlock(this);
            } else if (statement instanceof CSharpObjectCreationTree creation) {
                creation.setEnclosingBlock(this);
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
    public CSharpScope getScope() {
        return scope;
    }

    @Nonnull
    public List<CSharpTree> getStatements() {
        return statements;
    }
}
