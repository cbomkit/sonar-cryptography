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
package com.ibm.engine.language.cxx;

import com.ibm.engine.callstack.DetachedLocation;
import com.sonar.cxx.sslr.api.AstNode;
import com.sonar.cxx.sslr.api.GenericTokenType;
import com.sonar.cxx.sslr.api.Token;
import java.net.URI;
import java.util.List;
import javax.annotation.Nonnull;

/**
 * AST-free {@link AstNode} used as the location of a detached cross-file detection value.
 *
 * <p>Mirrors the engine's Java {@code DetachedSyntaxToken}: it fakes being a real parsed node so it
 * can flow through {@code CxxTranslator.getDetectionContextFrom(AstNode, ...)} and {@code
 * CxxLanguageTranslation} unchanged, but it holds only primitives captured at record time (never a
 * parent, children, or a reference back into the file's real AST), so it never pins the file's
 * parse tree. It has no parent and no children, so any traversal starting from it (ancestor/sibling
 * lookups) simply terminates immediately, which is correct for a leaf-only snapshot.
 *
 * <p>{@code CxxTranslator.getDetectionContextFrom} reads {@link AstNode#getToken()} (line/column)
 * and, via {@code extractKeywords}, falls through to {@link AstNode#getToken()}'s value since this
 * node's type never matches {@code postfixExpression}/{@code newExpression} — {@link #keywords()}
 * carries the richer, pre-extracted keyword list for callers that want it directly.
 */
public final class CxxDetachedAstNode extends AstNode implements DetachedLocation {

    @Nonnull private final List<String> keywords;

    public CxxDetachedAstNode(
            int line, int column, @Nonnull String text, @Nonnull List<String> keywords) {
        super(buildToken(line, column, text));
        this.keywords = List.copyOf(keywords);
    }

    @Nonnull
    public List<String> keywords() {
        return keywords;
    }

    @Nonnull
    private static Token buildToken(int line, int column, @Nonnull String text) {
        return Token.builder()
                .setType(GenericTokenType.LITERAL)
                .setValueAndOriginalValue(text)
                .setLine(Math.max(line, 1))
                .setColumn(Math.max(column, 0))
                .setURI(URI.create("detached:///cross-file"))
                .build();
    }
}
