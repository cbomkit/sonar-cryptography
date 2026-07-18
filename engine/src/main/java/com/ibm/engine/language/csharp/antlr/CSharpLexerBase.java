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
package com.ibm.engine.language.csharp.antlr;

import java.util.ArrayDeque;
import java.util.Deque;
import org.antlr.v4.runtime.CharStream;
import org.antlr.v4.runtime.CommonToken;
import org.antlr.v4.runtime.Lexer;
import org.antlr.v4.runtime.Token;

public abstract class CSharpLexerBase extends Lexer {

    protected CSharpLexerBase(CharStream input) {
        super(input);
    }

    protected int interpolatedStringLevel;
    protected final Deque<Boolean> interpolatedVerbatiums = new ArrayDeque<>();
    protected final Deque<Integer> curlyLevels = new ArrayDeque<>();
    protected boolean verbatium;

    protected void OnInterpolatedRegularStringStart() {
        interpolatedStringLevel++;
        interpolatedVerbatiums.push(false);
        verbatium = false;
    }

    protected void OnInterpolatedVerbatiumStringStart() {
        interpolatedStringLevel++;
        interpolatedVerbatiums.push(true);
        verbatium = true;
    }

    protected void OnOpenBrace() {
        if (interpolatedStringLevel > 0) {
            curlyLevels.push(curlyLevels.pop() + 1);
        }
    }

    protected void OnCloseBrace() {
        if (interpolatedStringLevel > 0) {
            curlyLevels.push(curlyLevels.pop() - 1);
            if (curlyLevels.peek() == 0) {
                curlyLevels.pop();
                skip();
                popMode();
            }
        }
    }

    protected void OnColon() {
        if (interpolatedStringLevel > 0) {
            int ind = 1;
            boolean switchToFormatString = true;
            while ((char) getInputStream().LA(ind) != '}') {
                if (getInputStream().LA(ind) == ':' || getInputStream().LA(ind) == ')') {
                    switchToFormatString = false;
                    break;
                }
                ind++;
            }
            if (switchToFormatString) {
                mode(CSharpLexer.INTERPOLATION_FORMAT);
            }
        }
    }

    protected void OpenBraceInside() {
        curlyLevels.push(1);
    }

    protected void OnDoubleQuoteInside() {
        interpolatedStringLevel--;
        interpolatedVerbatiums.pop();
        verbatium = (interpolatedVerbatiums.size() > 0 ? interpolatedVerbatiums.peek() : false);
    }

    protected void OnCloseBraceInside() {
        curlyLevels.pop();
    }

    protected boolean IsRegularCharInside() {
        return !verbatium;
    }

    protected boolean IsVerbatiumDoubleQuoteInside() {
        return verbatium;
    }

    // -------------------------------------------------------------------------
    // nextToken override — routes DIRECTIVE-channel tokens to HIDDEN
    // All preprocessor branches are kept visible so every crypto asset in the
    // source is reachable for detection, regardless of compile-time symbols.
    // -------------------------------------------------------------------------
    @Override
    public Token nextToken() {
        Token tok = super.nextToken();
        if (tok.getChannel() == CSharpLexer.DIRECTIVE) {
            // Route directive tokens to HIDDEN so the parser ignores the
            // directives themselves, but does NOT skip any code — both sides
            // of #if/#else remain in the token stream and are analysed.
            ((CommonToken) tok).setChannel(HIDDEN);
        }
        return tok;
    }
}
