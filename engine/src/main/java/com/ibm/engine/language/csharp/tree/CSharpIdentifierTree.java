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

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

/**
 * Represents a C# identifier (variable name, type name, etc.) used as an argument or in expressions
 * where the resolved value is not immediately known from the identifier's spelling alone.
 *
 * <p>Carries the {@link CSharpScope} it was created in, so {@code CSharpDetectionEngine} can look
 * up its declaration (a local variable, a {@code const}, or a parameter) rather than falling back
 * to the identifier's own name as a value — see {@code CSharpDetectionEngine}'s guard G1.
 */
public final class CSharpIdentifierTree implements CSharpTree {

    private final int line;
    private final int column;
    @Nonnull private final String name;
    @Nullable private final CSharpScope scope;

    public CSharpIdentifierTree(
            int line, int column, @Nonnull String name, @Nullable CSharpScope scope) {
        this.line = line;
        this.column = column;
        this.name = name;
        this.scope = scope;
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
        return name;
    }

    @Nonnull
    public String getName() {
        return name;
    }

    @Nullable @Override
    public CSharpScope getScope() {
        return scope;
    }
}
