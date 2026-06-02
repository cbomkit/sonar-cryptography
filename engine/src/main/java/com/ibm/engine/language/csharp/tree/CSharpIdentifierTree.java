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

/**
 * Represents a C# identifier (variable name, type name, etc.) used as an argument or in expressions
 * where the resolved value is not immediately known.
 */
public final class CSharpIdentifierTree implements CSharpTree {

    private final int line;
    private final int column;
    @Nonnull private final String name;

    public CSharpIdentifierTree(int line, int column, @Nonnull String name) {
        this.line = line;
        this.column = column;
        this.name = name;
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
}
