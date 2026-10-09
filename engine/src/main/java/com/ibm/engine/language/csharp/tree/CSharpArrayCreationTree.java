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
 * Represents a C# array creation expression, e.g. {@code new byte[32]} (explicit size) or {@code
 * new byte[] { 1, 2, 3 }} (size implied by the initializer).
 *
 * <p>This exists because array length is a very common way key/IV/salt/tag sizes are expressed in
 * {@code System.Security.Cryptography} code (e.g. {@code new AesGcm(new byte[32])}), mirroring the
 * {@code NEW_ARRAY} handling in the Java engine (array dimension used as a size, but only when the
 * requesting {@code IValueFactory} is a size factory — see {@code CSharpDetectionEngine}).
 */
public final class CSharpArrayCreationTree implements CSharpTree {

    private final int line;
    private final int column;

    /**
     * The element type, e.g. "byte". {@code null} for an implicitly-typed array ({@code new[]
     * {...}}).
     */
    @Nullable private final String elementType;

    /**
     * The size expression for {@code new T[expr]}; {@code null} when sized by an initializer
     * instead.
     */
    @Nullable private final CSharpTree lengthExpression;

    /**
     * Element count for {@code new T[] { ... }}; {@code -1} when an explicit {@link
     * #lengthExpression} is used instead.
     */
    private final int initializerElementCount;

    @Nullable private final CSharpScope scope;

    public CSharpArrayCreationTree(
            int line,
            int column,
            @Nullable String elementType,
            @Nullable CSharpTree lengthExpression,
            int initializerElementCount,
            @Nullable CSharpScope scope) {
        this.line = line;
        this.column = column;
        this.elementType = elementType;
        this.lengthExpression = lengthExpression;
        this.initializerElementCount = initializerElementCount;
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
        return "new " + (elementType != null ? elementType : "?") + "[]";
    }

    @Nullable @Override
    public CSharpScope getScope() {
        return scope;
    }

    @Nullable public String getElementType() {
        return elementType;
    }

    @Nullable public CSharpTree getLengthExpression() {
        return lengthExpression;
    }

    /** {@code -1} when this array was sized via {@link #getLengthExpression()} instead. */
    public int getInitializerElementCount() {
        return initializerElementCount;
    }
}
