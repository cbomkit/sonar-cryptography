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
 * <p>The {@code typeName} and {@code memberName} allow the detection engine to implement {@link
 * com.ibm.engine.language.ILanguageTranslation#getEnumClassName} and {@link
 * com.ibm.engine.language.ILanguageTranslation#getEnumIdentifierName}.
 */
public final class CSharpMemberAccessTree implements CSharpTree {

    private final int line;
    private final int column;

    /** The qualifier/type name (e.g. "CipherMode", "HashAlgorithmName", "ECCurve"). */
    @Nonnull private final String typeName;

    /** The member name (e.g. "CBC", "SHA256", "nistP256"). */
    @Nonnull private final String memberName;

    public CSharpMemberAccessTree(
            int line, int column, @Nonnull String typeName, @Nonnull String memberName) {
        this.line = line;
        this.column = column;
        this.typeName = typeName;
        this.memberName = memberName;
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
        return typeName + "." + memberName;
    }

    @Nonnull
    public String getTypeName() {
        return typeName;
    }

    @Nonnull
    public String getMemberName() {
        return memberName;
    }
}
