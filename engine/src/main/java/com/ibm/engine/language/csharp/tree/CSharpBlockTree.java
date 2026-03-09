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

/**
 * Represents a C# code block (method body, lambda, etc.), containing a list of statements.
 *
 * <p>This is the entry point for the detection engine — the sensor dispatches per-method blocks to
 * the engine for crypto pattern detection.
 */
public final class CSharpBlockTree implements CSharpTree {

    private final int line;
    private final int column;
    @Nonnull private final List<CSharpTree> statements;

    public CSharpBlockTree(int line, int column, @Nonnull List<CSharpTree> statements) {
        this.line = line;
        this.column = column;
        this.statements = statements;
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

    @Nonnull
    public List<CSharpTree> getStatements() {
        return statements;
    }
}
