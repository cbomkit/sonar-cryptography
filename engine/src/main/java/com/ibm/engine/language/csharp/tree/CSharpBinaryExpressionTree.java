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
 * Represents a simple two-operand arithmetic expression ({@code +}, {@code -}, {@code *}, {@code
 * /}, {@code %}), e.g. {@code 256 / 8} or {@code keyBits * 2}.
 *
 * <p>Conversion only recognizes the flat two-operand shape (not longer chains like {@code a+b+c});
 * the actual constant folding happens lazily in {@code CSharpDetectionEngine.resolveValues} when a
 * value is actually requested, consistent with how identifiers are resolved lazily via {@link
 * CSharpScope} rather than eagerly at parse time.
 */
public final class CSharpBinaryExpressionTree implements CSharpTree {

    private final int line;
    private final int column;
    @Nonnull private final CSharpTree left;
    @Nonnull private final String operator;
    @Nonnull private final CSharpTree right;
    @Nullable private final CSharpScope scope;

    public CSharpBinaryExpressionTree(
            int line,
            int column,
            @Nonnull CSharpTree left,
            @Nonnull String operator,
            @Nonnull CSharpTree right,
            @Nullable CSharpScope scope) {
        this.line = line;
        this.column = column;
        this.left = left;
        this.operator = operator;
        this.right = right;
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
        return left.getText() + " " + operator + " " + right.getText();
    }

    @Nullable @Override
    public CSharpScope getScope() {
        return scope;
    }

    @Nonnull
    public CSharpTree getLeft() {
        return left;
    }

    @Nonnull
    public String getOperator() {
        return operator;
    }

    @Nonnull
    public CSharpTree getRight() {
        return right;
    }
}
