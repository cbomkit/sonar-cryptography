/*
 * Sonar Cryptography Plugin
 * Copyright (C) 2026 PQCA
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
package com.ibm.plugin;

import java.util.ArrayDeque;
import java.util.Deque;
import javax.annotation.Nonnull;

/**
 * Neutralizes C# conditional compilation directives before the source is lexed, so that code inside
 * {@code #if} is analysed instead of skipped.
 *
 * <h2>Why this is needed</h2>
 *
 * <p>The grammar skips the body of an {@code #if} region outright, because it has no notion of
 * which conditional symbols a build defines. Every symbol is therefore effectively undefined and
 * every such region disappears. That is not a corner case: whole files in real .NET libraries are
 * wrapped in one, and two of the three cryptography-bearing files in ASP.NET Core's Data Protection
 * stack are, which is how {@code Rfc2898DeriveBytes.Pbkdf2} and {@code new AesGcm(...)} were being
 * missed entirely there while the same calls were detected in a file without the directive.
 *
 * <h2>What it does, and why that is the right answer</h2>
 *
 * <p>Each line whose first non-whitespace content is {@code #if}, {@code #elif}, {@code #else} or
 * {@code #endif} is replaced by spaces. Every branch then becomes ordinary code and all of it is
 * analysed.
 *
 * <p>Making every branch visible is the correct behaviour for a bill of materials, not a
 * compromise. A component that reaches for AES-GCM under one build configuration and Triple DES
 * under another contains both, and a reader deciding whether to trust it needs to see both. A
 * compiler must choose one branch; an inventory must not.
 *
 * <p>Where the branches disagree about a value rather than about which algorithm is used, the
 * result is not a wrong value: a variable assigned differently in two branches is exactly the
 * conflicting-reassignment case the engine already refuses to resolve, so the algorithm is reported
 * and the value is left absent.
 *
 * <p>Replacing with spaces rather than deleting keeps every byte offset, line and column intact, so
 * a finding still points at the line it came from. This is also why the directive is not evaluated:
 * evaluating it would require knowing the build's symbols, which a source scan does not, and
 * guessing at them would silently hide code.
 *
 * <p>{@code #pragma}, {@code #nullable}, {@code #region}, {@code #define}, {@code #line}, {@code
 * #warning} and {@code #error} are left untouched. They do not suppress code and the grammar
 * already handles them.
 *
 * <h2>Why there are two modes</h2>
 *
 * <p>Activating every branch is not always syntactically valid, because a conditional block may
 * split a single construct rather than enclose whole ones. Real example from
 * Microsoft.IdentityModel:
 *
 * <pre>
 * public static string ClientSku =&gt;
 * #if NET462
 *     "ID_NET462";
 * #elif NET472
 *     "ID_NET472";
 * #endif
 * </pre>
 *
 * <p>With both branches active that reads as one expression-bodied member followed by a bare string
 * literal statement, which does not parse, and the parse failure costs the rest of the file. So
 * {@link #neutralize} is only the first attempt. {@link #selectFirstBranch} is the fallback: it
 * keeps the first branch of each conditional chain and blanks the alternatives. Exactly one active
 * branch per chain reproduces what a compiler sees for one build configuration, so the result is
 * valid by construction and the file parses. The caller tries the broad mode first and falls back
 * on a parse error, which keeps full coverage for the common case of a conditional that wraps whole
 * declarations while never losing a file to the case that splits one.
 */
public final class CSharpConditionalDirectives {

    private CSharpConditionalDirectives() {
        // utility
    }

    /**
     * Returns {@code source} with only the first branch of each conditional chain left active, the
     * alternatives blanked out and every offset preserved.
     *
     * <p>This is the fallback for sources that {@link #neutralize} cannot keep parseable. Because
     * one branch per chain is what a compiler sees for some set of conditional symbols, brace
     * balance and construct boundaries hold automatically. The cost is that cryptography appearing
     * only in an {@code #elif} or {@code #else} branch is not seen, which is the lesser loss
     * against dropping the file.
     */
    @Nonnull
    public static String selectFirstBranch(@Nonnull String source) {
        if (!containsConditionalDirective(source)) {
            return source;
        }
        final char[] chars = source.toCharArray();
        // One entry per open conditional chain: true while we are inside its first branch.
        final Deque<Boolean> inFirstBranch = new ArrayDeque<>();
        int lineStart = 0;
        for (int i = 0; i <= chars.length; i++) {
            if (i < chars.length && chars[i] != '\n' && chars[i] != '\r') {
                continue;
            }
            final Directive directive = classifyLine(chars, lineStart, i);
            switch (directive) {
                case IF -> inFirstBranch.push(Boolean.TRUE);
                case ELIF_OR_ELSE -> {
                    if (!inFirstBranch.isEmpty()) {
                        inFirstBranch.pop();
                        inFirstBranch.push(Boolean.FALSE);
                    }
                }
                case ENDIF -> {
                    if (!inFirstBranch.isEmpty()) {
                        inFirstBranch.pop();
                    }
                }
                case NONE -> {
                    // A body line survives only if every enclosing chain is in its first branch.
                    if (inFirstBranch.contains(Boolean.FALSE)) {
                        blank(chars, lineStart, i);
                    }
                    lineStart = i + 1;
                    continue;
                }
            }
            blank(chars, lineStart, i);
            lineStart = i + 1;
        }
        return new String(chars);
    }

    private enum Directive {
        IF,
        ELIF_OR_ELSE,
        ENDIF,
        NONE
    }

    @Nonnull
    private static Directive classifyLine(@Nonnull char[] chars, int start, int end) {
        int i = start;
        while (i < end && (chars[i] == ' ' || chars[i] == '\t')) {
            i++;
        }
        if (i >= end || chars[i] != '#') {
            return Directive.NONE;
        }
        final String rest = new String(chars, i, end - i);
        int k = 1;
        while (k < rest.length() && (rest.charAt(k) == ' ' || rest.charAt(k) == '\t')) {
            k++;
        }
        if (rest.startsWith("endif", k) && isKeywordEnd(rest, k + 5)) {
            return Directive.ENDIF;
        }
        if (rest.startsWith("elif", k) && isKeywordEnd(rest, k + 4)) {
            return Directive.ELIF_OR_ELSE;
        }
        if (rest.startsWith("else", k) && isKeywordEnd(rest, k + 4)) {
            return Directive.ELIF_OR_ELSE;
        }
        if (rest.startsWith("if", k) && isKeywordEnd(rest, k + 2)) {
            return Directive.IF;
        }
        return Directive.NONE;
    }

    private static void blank(@Nonnull char[] chars, int start, int end) {
        for (int j = start; j < end; j++) {
            chars[j] = ' ';
        }
    }

    /** Returns {@code source} with conditional directive lines blanked out, length preserved. */
    @Nonnull
    public static String neutralize(@Nonnull String source) {
        if (!containsConditionalDirective(source)) {
            return source;
        }
        final char[] chars = source.toCharArray();
        int lineStart = 0;
        for (int i = 0; i <= chars.length; i++) {
            if (i == chars.length || chars[i] == '\n' || chars[i] == '\r') {
                blankIfConditionalDirective(chars, lineStart, i);
                lineStart = i + 1;
            }
        }
        return new String(chars);
    }

    /**
     * A cheap pre-check so that the common case, a file with no conditional directive at all, costs
     * one scan of the text and no allocation.
     */
    private static boolean containsConditionalDirective(@Nonnull String source) {
        int from = source.indexOf('#');
        while (from >= 0) {
            if (startsConditionalDirective(source, from)) {
                return true;
            }
            from = source.indexOf('#', from + 1);
        }
        return false;
    }

    private static void blankIfConditionalDirective(@Nonnull char[] chars, int start, int end) {
        int i = start;
        while (i < end && (chars[i] == ' ' || chars[i] == '\t')) {
            i++;
        }
        if (i >= end || chars[i] != '#') {
            return;
        }
        if (!startsConditionalDirective(new String(chars, i, end - i), 0)) {
            return;
        }
        for (int j = start; j < end; j++) {
            chars[j] = ' ';
        }
    }

    /**
     * Whether the {@code #} at {@code hashIndex} begins a conditional directive. The keyword may be
     * separated from the {@code #} by whitespace, which C# permits, and must be followed by
     * whitespace or the end of the line so that a longer word is not matched.
     */
    private static boolean startsConditionalDirective(@Nonnull String text, int hashIndex) {
        int i = hashIndex + 1;
        while (i < text.length() && (text.charAt(i) == ' ' || text.charAt(i) == '\t')) {
            i++;
        }
        for (String keyword : new String[] {"endif", "elif", "else", "if"}) {
            if (text.startsWith(keyword, i) && isKeywordEnd(text, i + keyword.length())) {
                return true;
            }
        }
        return false;
    }

    private static boolean isKeywordEnd(@Nonnull String text, int index) {
        if (index >= text.length()) {
            return true;
        }
        char c = text.charAt(index);
        return !Character.isLetterOrDigit(c) && c != '_';
    }
}
