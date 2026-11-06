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

import javax.annotation.Nonnull;

/** A string, number, boolean or {@code null} literal. */
public final class JavaScriptLiteralTree implements JavaScriptTree {

    /** The syntactic kind of the literal. */
    public enum Kind {
        STRING,
        NUMBER,
        BOOLEAN,
        NULL
    }

    private final int line;
    private final int column;
    @Nonnull private final Kind kind;
    @Nonnull private final String value;

    public JavaScriptLiteralTree(int line, int column, @Nonnull Kind kind, @Nonnull String value) {
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

    /** The literal's value, without surrounding quotes for strings. */
    @Nonnull
    public String getValue() {
        return value;
    }
}
