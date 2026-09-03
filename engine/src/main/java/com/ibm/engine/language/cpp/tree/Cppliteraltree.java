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
package com.ibm.engine.language.cpp.tree;

import javax.annotation.Nonnull;

/**
 * A C/C++ tree node representing a literal value — either a string literal or a numeric constant.
 *
 * <p>Examples of what this node captures:
 *
 * <ul>
 *   <li>String literal used as an algorithm name: {@code "AES-256-CBC"}, {@code "SHA256"}
 *   <li>Integer constant used as a key size: {@code 256}, {@code 2048}, {@code 128}
 *   <li>Hex constant: {@code 0x100}
 * </ul>
 *
 * <p>This is one of the most important node types for crypto detection, because OpenSSL functions
 * frequently receive algorithm identifiers as string literals or key sizes as integer constants.
 *
 * <p>Example C code producing this node:
 *
 * <pre>{@code
 * EVP_DigestInit_ex(ctx, EVP_get_digestbyname("SHA256"), NULL);
 * RSA_generate_key_ex(rsa, 2048, e, NULL);
 * }</pre>
 */
public final class CppLiteralTree implements CppTree {

    /** The raw text of the literal exactly as it appears in source, e.g. {@code "AES-256-CBC"} or {@code 256}. */
    @Nonnull private final String value;

    /** Whether this literal is a string (quoted) rather than a numeric constant. */
    private final boolean isString;

    private final int line;
    private final int column;

    /**
     * Creates a new {@code CppLiteralTree}.
     *
     * @param value the raw literal text as it appears in source code (including quotes for strings)
     * @param isString {@code true} if this is a string literal, {@code false} for numeric
     * @param line 1-based line number in the source file
     * @param column 0-based column offset within the line
     */
    public CppLiteralTree(@Nonnull String value, boolean isString, int line, int column) {
        this.value = value;
        this.isString = isString;
        this.line = line;
        this.column = column;
    }

    /**
     * Returns the raw text of the literal as it appears in source code.
     *
     * <p>For string literals this includes the surrounding quotes, e.g. {@code "AES-256-CBC"}.
     * Call {@link #unquotedValue()} to get the content without quotes.
     *
     * @return the raw literal text, never {@code null}
     */
    @Nonnull
    public String value() {
        return value;
    }

    /**
     * Returns the string content without surrounding double-quotes.
     *
     * <p>For example, if the source code contained {@code "AES-256-CBC"}, this method returns
     * {@code AES-256-CBC}.
     *
     * <p>For numeric literals, this is the same as {@link #value()}.
     *
     * @return the unquoted value
     */
    @Nonnull
    public String unquotedValue() {
        if (isString && value.length() >= 2 && value.startsWith("\"") && value.endsWith("\"")) {
            return value.substring(1, value.length() - 1);
        }
        return value;
    }

    /**
     * Returns {@code true} if this literal is a string (enclosed in double quotes).
     *
     * @return {@code true} for string literals, {@code false} for numeric constants
     */
    public boolean isString() {
        return isString;
    }

    @Override
    public Kind kind() {
        return Kind.LITERAL;
    }

    @Override
    public int line() {
        return line;
    }

    @Override
    public int column() {
        return column;
    }

    @Override
    public String toString() {
        return "CppLiteralTree{value=" + value + ", line=" + line + "}";
    }
}
