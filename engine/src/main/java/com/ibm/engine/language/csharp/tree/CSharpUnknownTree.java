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
 * An argument whose value this converter cannot determine — a ternary with differing branches, an
 * element access, a switch expression, a call into another file.
 *
 * <p>It exists so that such an argument still <em>occupies its position</em>. A rule's parameter
 * list is matched against the call's arity, so silently dropping an unconvertible argument would
 * change {@code RSA.Create(sizes[0])} from a one-argument call into a zero-argument one and stop
 * the RSA detection from firing at all — losing the algorithm, not just the key size. Resolution
 * simply has no branch for this node, so it yields no value, and {@code CSharpTypeInference} infers
 * no type for it, so it never blocks a rule that declares a concrete parameter type.
 */
public final class CSharpUnknownTree implements CSharpTree {

    private final int line;
    private final int column;
    @Nonnull private final String text;

    public CSharpUnknownTree(int line, int column, @Nonnull String text) {
        this.line = line;
        this.column = column;
        this.text = text;
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
        return text;
    }
}
