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
 * Represents a C# literal value (string, integer, boolean, etc.).
 *
 * <p>The {@code value} field contains the raw literal text as it appears in source code. For string
 * literals, the surrounding quotes are stripped.
 */
public final class CSharpLiteralTree implements CSharpTree {

    /** Literal kind. */
    public enum Kind {
        STRING,
        INTEGER,
        REAL,
        BOOLEAN,
        CHARACTER,
        NULL
    }

    private final int line;
    private final int column;
    @Nonnull private final Kind kind;

    /** The literal value. For strings: content without quotes. For integers: the numeric string. */
    @Nonnull private final String value;

    public CSharpLiteralTree(int line, int column, @Nonnull Kind kind, @Nonnull String value) {
        this.line = line;
        this.column = column;
        this.kind = kind;
        this.value = value;
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
        return value;
    }

    @Nonnull
    public Kind getKind() {
        return kind;
    }

    @Nonnull
    public String getValue() {
        return value;
    }
}
