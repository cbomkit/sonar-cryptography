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
package com.ibm.engine.callstack;

import java.util.List;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.sonar.plugins.java.api.location.Position;
import org.sonar.plugins.java.api.location.Range;
import org.sonar.plugins.java.api.tree.SyntaxToken;
import org.sonar.plugins.java.api.tree.SyntaxTrivia;
import org.sonar.plugins.java.api.tree.Tree;
import org.sonar.plugins.java.api.tree.TreeVisitor;

/**
 * AST-free {@link SyntaxToken} used as the location of a detached cross-file detection value.
 *
 * <p>It holds only primitives captured at record time, so it never pins a compilation unit ({@link
 * #parent()} is {@code null}). The Java translator reads {@link #line()}, {@link #offset()} and
 * {@link #keywords()} from it directly to build a {@code DetectionLocation} without touching a live
 * tree. Column offsets are stored 0-based (matching {@link Position#columnOffset()}); {@link
 * Position#at(int, int)} takes a 1-based column, so {@link #range()} adds one.
 */
public final class DetachedSyntaxToken implements SyntaxToken {

    private final int line;
    private final int columnOffset;
    private final int endLine;
    private final int endColumnOffset;
    @Nonnull private final String text;
    @Nonnull private final List<String> keywords;

    public DetachedSyntaxToken(
            int line,
            int columnOffset,
            int endLine,
            int endColumnOffset,
            @Nonnull String text,
            @Nonnull List<String> keywords) {
        this.line = line;
        this.columnOffset = columnOffset;
        this.endLine = endLine;
        this.endColumnOffset = endColumnOffset;
        this.text = text;
        this.keywords = List.copyOf(keywords);
    }

    @Nonnull
    public List<String> keywords() {
        return keywords;
    }

    /** 0-based start column offset, matching {@code DetectionLocation}'s offset field. */
    public int offset() {
        return columnOffset;
    }

    /** 1-based end line of the captured range. */
    public int endLine() {
        return endLine;
    }

    /** 0-based end column offset of the captured range. */
    public int endOffset() {
        return endColumnOffset;
    }

    @Override
    public String text() {
        return text;
    }

    @Override
    public List<SyntaxTrivia> trivias() {
        return List.of();
    }

    @Override
    public int line() {
        return line;
    }

    @Override
    public int column() {
        return columnOffset;
    }

    @Override
    public Range range() {
        return Range.at(
                Position.at(line, columnOffset + 1), Position.at(endLine, endColumnOffset + 1));
    }

    @Override
    public boolean is(Tree.Kind... kinds) {
        for (Tree.Kind kind : kinds) {
            if (kind == Tree.Kind.TOKEN) {
                return true;
            }
        }
        return false;
    }

    @Override
    public void accept(TreeVisitor visitor) {
        // Detached: not part of an AST, nothing to traverse.
    }

    @Nullable @Override
    public Tree parent() {
        return null;
    }

    @Override
    public SyntaxToken firstToken() {
        return this;
    }

    @Override
    public SyntaxToken lastToken() {
        return this;
    }

    @Override
    public Tree.Kind kind() {
        return Tree.Kind.TOKEN;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof DetachedSyntaxToken that)) {
            return false;
        }
        return line == that.line
                && columnOffset == that.columnOffset
                && endLine == that.endLine
                && endColumnOffset == that.endColumnOffset
                && text.equals(that.text)
                && keywords.equals(that.keywords);
    }

    @Override
    public int hashCode() {
        int result = line;
        result = 31 * result + columnOffset;
        result = 31 * result + endLine;
        result = 31 * result + endColumnOffset;
        result = 31 * result + text.hashCode();
        result = 31 * result + keywords.hashCode();
        return result;
    }
}
