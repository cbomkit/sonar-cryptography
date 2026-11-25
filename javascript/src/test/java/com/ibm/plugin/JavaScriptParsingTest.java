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

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.plugin.javascript.language.JavaScriptParsing;
import org.junit.jupiter.api.Test;

class JavaScriptParsingTest {

    @Test
    void parsesTypedTypeScript() {
        String source =
                "import * as crypto from 'node:crypto';\n"
                        + "interface P { body: string }\n"
                        + "function f(p: P): string {\n"
                        + "  return crypto.createHash('sha256').update(p.body).digest('hex');\n"
                        + "}\n";
        assertThat(JavaScriptParsing.parse(source, "a.ts").syntaxErrors()).isZero();
    }

    @Test
    void parsesPlainJavaScriptAndModernSyntax() {
        String source = "const h = require('crypto').createHash('md5'); const x = a?.b ?? c;\n";
        assertThat(JavaScriptParsing.parse(source, "a.js").syntaxErrors()).isZero();
    }

    @Test
    void reportsSyntaxErrorsInBrokenSource() {
        assertThat(JavaScriptParsing.parse("function ( {{ ", "bad.ts").syntaxErrors()).isPositive();
    }
}
