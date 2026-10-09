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

import org.junit.jupiter.api.Test;

/** Unit tests for {@link CSharpConditionalDirectives}. */
class CSharpConditionalDirectivesTest {

    @Test
    void blanksConditionalDirectivesAndKeepsEveryOffset() {
        String source =
                "#if NETCOREAPP\n"
                        + "  #if DEBUG\n"
                        + "int a = 1;\n"
                        + "  # else\n"
                        + "int a = 2;\n"
                        + "#elif OTHER\n"
                        + "int a = 3;\n"
                        + "#endif\n"
                        + "#endif\n";
        String result = CSharpConditionalDirectives.neutralize(source);

        // Every branch's code survives, so all of it is analysed.
        assertThat(result).contains("int a = 1;", "int a = 2;", "int a = 3;");
        // No directive keyword is left for the grammar to act on.
        assertThat(result).doesNotContain("#if", "#elif", "#else", "#endif", "# else");
        // Offsets, lines and columns are untouched, so findings still point at the right place.
        assertThat(result).hasSameSizeAs(source);
        assertThat(result.lines().count()).isEqualTo(source.lines().count());
        assertThat(result.indexOf("int a = 1;")).isEqualTo(source.indexOf("int a = 1;"));
        assertThat(result.indexOf("int a = 3;")).isEqualTo(source.indexOf("int a = 3;"));
    }

    @Test
    void firstBranchModeKeepsOneBranchAndBlanksTheAlternatives() {
        String source =
                "#if NET462\n"
                        + "int a = 1;\n"
                        + "#elif NET472\n"
                        + "int a = 2;\n"
                        + "#else\n"
                        + "int a = 3;\n"
                        + "#endif\n";
        String result = CSharpConditionalDirectives.selectFirstBranch(source);

        // Exactly one branch survives, which is what a compiler sees for one configuration and is
        // therefore always valid C#.
        assertThat(result).contains("int a = 1;");
        assertThat(result).doesNotContain("int a = 2;", "int a = 3;");
        assertThat(result).doesNotContain("#if", "#elif", "#else", "#endif");
        // Offsets are preserved, so a finding still points at the right line.
        assertThat(result).hasSameSizeAs(source);
        assertThat(result.indexOf("int a = 1;")).isEqualTo(source.indexOf("int a = 1;"));
    }

    @Test
    void firstBranchModeHandlesNesting() {
        String source =
                "#if OUTER\n"
                        + "int kept = 1;\n"
                        + "#if INNER\n"
                        + "int alsoKept = 2;\n"
                        + "#else\n"
                        + "int dropped = 3;\n"
                        + "#endif\n"
                        + "#else\n"
                        + "int droppedToo = 4;\n"
                        + "#endif\n";
        String result = CSharpConditionalDirectives.selectFirstBranch(source);

        assertThat(result).contains("int kept = 1;", "int alsoKept = 2;");
        assertThat(result).doesNotContain("int dropped = 3;", "int droppedToo = 4;");
        assertThat(result).hasSameSizeAs(source);
    }

    @Test
    void leavesOtherDirectivesAlone() {
        String source =
                "#pragma warning disable CS0618\n"
                        + "#nullable enable\n"
                        + "#region Keys\n"
                        + "#define TRACE\n"
                        + "#line 42\n"
                        + "#warning careful\n"
                        + "#endregion\n";
        assertThat(CSharpConditionalDirectives.neutralize(source)).isEqualTo(source);
    }

    @Test
    void leavesTextWithoutConditionalDirectivesUnchanged() {
        String source = "var s = \"#if not a directive\";\nint ifCount = 1;\n";
        assertThat(CSharpConditionalDirectives.neutralize(source)).isEqualTo(source);
        assertThat(CSharpConditionalDirectives.selectFirstBranch(source)).isEqualTo(source);
    }

    @Test
    void doesNotMatchALongerWordBeginningWithADirectiveKeyword() {
        String source = "#ifdefined FOO\nint a = 1;\n";
        assertThat(CSharpConditionalDirectives.neutralize(source)).isEqualTo(source);
    }
}
