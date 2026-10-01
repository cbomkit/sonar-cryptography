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
package com.ibm.engine.language.c.tree;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import javax.annotation.Nonnull;

/**
 * Represents a block of statements in C/C++ source code (typically a function body).
 *
 * <p>This is the entry point for the detection engine — the sensor dispatches per-function blocks to
 * the engine for crypto pattern detection.
 */
public final class CBlockTree implements CTree {

    private final int line;
    private final int column;
    @Nonnull private final List<CTree> statements;

    public CBlockTree(int line, int column, @Nonnull List<CTree> statements) {
        this.line = line;
        this.column = column;
        this.statements = new ArrayList<>(statements);
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
    public List<CTree> getStatements() {
        return Collections.unmodifiableList(statements);
    }
}
