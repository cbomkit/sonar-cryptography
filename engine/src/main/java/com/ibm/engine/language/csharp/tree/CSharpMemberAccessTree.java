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
 * Represents a C# member access expression such as {@code CipherMode.CBC} or {@code
 * ECCurve.NamedCurves.nistP256}.
 *
 * <p>Used for enum-like values in C# that are passed as arguments:
 *
 * <pre>
 *   aes.Mode = CipherMode.CBC;
 *   var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
 *   new Rfc2898DeriveBytes(pwd, salt, iter, HashAlgorithmName.SHA256);
 * </pre>
 *
 * <p>C# member access chains can be arbitrarily deep ({@code A.B.C.D}). This node keeps the full
 * dotted chain: {@link #getRootType()} is the leftmost segment ({@code "ECCurve"}), {@link
 * #getQualifier()} is everything up to (but excluding) the final segment ({@code
 * "ECCurve.NamedCurves"}), and {@link #getMemberName()} is the final segment ({@code "nistP256"}) —
 * the one that should be used as the resolved value. Earlier versions of this class only kept the
 * first two segments, which meant a three-level chain like {@code ECCurve.NamedCurves.nistP256}
 * resolved to the meaningless middle segment {@code "NamedCurves"} instead of the actual curve
 * name.
 *
 * <p>{@link #getTypeName()} is kept as an alias of {@link #getRootType()} for the two-level case
 * ({@code CipherMode.CBC}), which is by far the most common shape and is what most existing
 * detection rules and {@code ILanguageTranslation#getEnumClassName} rely on.
 */
public final class CSharpMemberAccessTree implements CSharpTree {

    private final int line;
    private final int column;

    /** The leftmost segment of the chain (e.g. "ECCurve", "CipherMode"). */
    @Nonnull private final String rootType;

    /** Everything up to (but excluding) the final segment (e.g. "ECCurve.NamedCurves"). */
    @Nonnull private final String qualifier;

    /** The final segment — the member/value name (e.g. "nistP256", "CBC", "SHA256"). */
    @Nonnull private final String memberName;

    public CSharpMemberAccessTree(
            int line,
            int column,
            @Nonnull String rootType,
            @Nonnull String qualifier,
            @Nonnull String memberName) {
        this.line = line;
        this.column = column;
        this.rootType = rootType;
        this.qualifier = qualifier;
        this.memberName = memberName;
    }

    /** Convenience constructor for a simple two-level access ({@code Type.Member}). */
    public CSharpMemberAccessTree(
            int line, int column, @Nonnull String typeName, @Nonnull String memberName) {
        this(line, column, typeName, typeName, memberName);
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
        return qualifier + "." + memberName;
    }

    /** Alias of {@link #getRootType()}, kept for the common two-level-access call sites. */
    @Nonnull
    public String getTypeName() {
        return rootType;
    }

    @Nonnull
    public String getRootType() {
        return rootType;
    }

    @Nonnull
    public String getQualifier() {
        return qualifier;
    }

    @Nonnull
    public String getMemberName() {
        return memberName;
    }
}
