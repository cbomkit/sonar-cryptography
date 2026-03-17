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

import java.util.HashSet;
import java.util.Set;
import org.antlr.v4.runtime.Parser;
import org.antlr.v4.runtime.Token;
import org.antlr.v4.runtime.TokenStream;

public abstract class CSharpParserBase extends Parser {
    private static final String[] ALL_SEMANTIC_FUNCTIONS = {"IsLocalVariableDeclaration"};

    private final Set<String> noSemantics;

    protected CSharpParserBase(TokenStream input) {
        super(input);
        noSemantics = parseNoSemantics(System.getProperty("sun.java.command", "").split("\\s+"));
    }

    private static Set<String> parseNoSemantics(String[] args) {
        Set<String> result = new HashSet<>();
        for (String a : args) {
            if (a.toLowerCase().startsWith("--no-semantics")) {
                int eq = a.indexOf('=');
                if (eq == -1) {
                    for (String f : ALL_SEMANTIC_FUNCTIONS) result.add(f);
                } else {
                    for (String f : a.substring(eq + 1).split(",")) result.add(f.trim());
                }
            }
        }
        return result;
    }

    protected boolean IsRightArrow() {
        return areAdjacent();
    }

    protected boolean IsRightShift() {
        return areAdjacent();
    }

    protected boolean IsRightShiftAssignment() {
        return areAdjacent();
    }

    private boolean areAdjacent() {
        Token first = _input.LT(-2);
        Token second = _input.LT(-1);
        return first != null
                && second != null
                && first.getTokenIndex() + 1 == second.getTokenIndex();
    }

    protected boolean IsLocalVariableDeclaration() {
        if (noSemantics.contains("IsLocalVariableDeclaration")) return true;
        if (!(this._ctx instanceof CSharpParser.Local_variable_declarationContext)) {
            return false;
        }
        CSharpParser.Local_variable_declarationContext local_var_decl =
                (CSharpParser.Local_variable_declarationContext) this._ctx;
        CSharpParser.Local_variable_typeContext local_variable_type =
                local_var_decl.local_variable_type();
        if (local_variable_type == null) return true;
        if (local_variable_type.getText().equals("var")) return false;
        return true;
    }
}
