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
import javax.annotation.Nullable;

/**
 * Represents a C/C++ function call expression such as {@code EVP_EncryptInit_ex(ctx,
 * EVP_aes_128_cbc(), ...)}.
 *
 * <p>The {@code objectTypeName} maps the function to a library namespace (e.g. {@code "EVP"} for
 * {@code EVP_EncryptInit_ex}), allowing the engine's type-matching infrastructure to work with C's
 * flat function namespace.
 */
public final class CFunctionCallTree implements CTree {

    private final int line;
    private final int column;

    /** The function name (e.g. "EVP_EncryptInit_ex"). */
    @Nonnull private final String functionName;

    /** The library/namespace prefix (e.g. "EVP"). */
    @Nonnull private final String objectTypeName;

    /** The argument trees in call order. */
    @Nonnull private final List<CTree> arguments;

    /** Optional identifier this call result is assigned to (for depending rule tracking). */
    @Nullable private final String assignedIdentifier;

    /** The enclosing block tree (for depending rule context). */
    @Nullable private final CBlockTree enclosingBlock;

    public CFunctionCallTree(
            int line,
            int column,
            @Nonnull String functionName,
            @Nonnull String objectTypeName,
            @Nonnull List<CTree> arguments,
            @Nullable String assignedIdentifier,
            @Nullable CBlockTree enclosingBlock) {
        this.line = line;
        this.column = column;
        this.functionName = functionName;
        this.objectTypeName = objectTypeName;
        this.arguments = new ArrayList<>(arguments);
        this.assignedIdentifier = assignedIdentifier;
        this.enclosingBlock = enclosingBlock;
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
        return objectTypeName + "::" + functionName + "(" + arguments.size() + " args)";
    }

    @Nonnull
    public String getFunctionName() {
        return functionName;
    }

    @Nonnull
    public String getObjectTypeName() {
        return objectTypeName;
    }

    @Nonnull
    public List<CTree> getArguments() {
        return Collections.unmodifiableList(arguments);
    }

    @Nullable
    public String getAssignedIdentifier() {
        return assignedIdentifier;
    }

    @Nullable
    public CBlockTree getEnclosingBlock() {
        return enclosingBlock;
    }
}
