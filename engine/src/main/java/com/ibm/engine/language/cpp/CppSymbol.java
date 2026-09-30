/*
 * Sonar Cryptography Plugin
 * Copyright (C) 2025 PQCA
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
package com.ibm.engine.language.cpp;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

/**
 * Represents a symbol (variable, function, or type name) in C/C++ source code.
 *
 * <p>This class fills the {@code S} (Symbol) generic type parameter used throughout the engine. It
 * is the C/C++ equivalent of {@code Symbol} in the Java language support and {@code CSharpSymbol}
 * in the C# language support.
 *
 * <p>In C/C++, because we use ANTLR for parsing (not a full Sonar language analyzer), we do not
 * have a rich semantic model with full type resolution. This class therefore provides a lightweight
 * symbol representation based on the identifier name and its resolved string value (if any).
 *
 * <p>Known limitation: unlike Java's {@code Symbol}, this class does not support cross-method
 * variable tracking. Symbol resolution is limited to single-function scope, consistent with the
 * current C# implementation approach.
 */
public final class CppSymbol {

    /** The name of the identifier as it appears in source code (e.g., {@code "ctx"}, {@code "key"}). */
    @Nonnull private final String name;

    /**
     * The resolved string value of this symbol, if it can be statically determined. For example,
     * if the code contains {@code const char *algo = "AES-256-CBC"}, then {@code resolvedValue}
     * would be {@code "AES-256-CBC"}. {@code null} if the value cannot be statically resolved.
     */
    @Nullable private final String resolvedValue;

    /**
     * Creates a new {@code CppSymbol} with a name and no resolved value.
     *
     * @param name the identifier name as it appears in source code
     */
    public CppSymbol(@Nonnull String name) {
        this.name = name;
        this.resolvedValue = null;
    }

    /**
     * Creates a new {@code CppSymbol} with both a name and a statically resolved value.
     *
     * @param name the identifier name as it appears in source code
     * @param resolvedValue the statically resolved string value, or {@code null} if not resolvable
     */
    public CppSymbol(@Nonnull String name, @Nullable String resolvedValue) {
        this.name = name;
        this.resolvedValue = resolvedValue;
    }

    /**
     * Returns the identifier name as it appears in source code.
     *
     * @return the symbol name, never {@code null}
     */
    @Nonnull
    public String name() {
        return name;
    }

    /**
     * Returns the statically resolved string value of this symbol, if available.
     *
     * @return the resolved value, or {@code null} if it cannot be statically determined
     */
    @Nullable
    public String resolvedValue() {
        return resolvedValue;
    }

    /**
     * Returns {@code true} if this symbol has a statically resolved value.
     *
     * @return {@code true} if {@link #resolvedValue()} is non-null
     */
    public boolean isResolved() {
        return resolvedValue != null;
    }

    @Override
    public String toString() {
        if (resolvedValue != null) {
            return "CppSymbol{name='" + name + "', resolvedValue='" + resolvedValue + "'}";
        }
        return "CppSymbol{name='" + name + "'}";
    }
}
