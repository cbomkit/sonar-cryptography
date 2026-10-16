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

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.language.csharp.CSharpCheck;
import com.ibm.engine.language.csharp.CSharpScanContext;
import com.ibm.engine.language.csharp.CSharpSymbol;
import com.ibm.engine.language.csharp.tree.CSharpTree;
import com.ibm.mapper.model.INode;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;

/**
 * Pins that a byte order mark in front of an opening conditional directive does not cost the file.
 *
 * <p>{@link CSharpConditionalDirectivesTest} covers the preprocessing in isolation; this covers it
 * through the detection path, where the consequence is visible. A file written by Visual Studio
 * begins with U+FEFF, so one whose first line is {@code #if} has the mark in front of the {@code
 * #}. While only spaces and tabs counted as directive indentation, that opening directive went
 * unrecognised and stayed in place while its {@code #endif} was blanked. The grammar evaluates
 * conditional directives in the lexer itself, so the surviving {@code #if} suppressed everything
 * after it: no parse error, just an empty token stream and a file that produced nothing.
 *
 * <p>A sensor run is not affected, because SonarQube's file reading strips the mark before this
 * code sees it. This harness does not, which is exactly why the case is worth pinning here: it is
 * the caller that would otherwise disagree with production, and the fixture below is the shape -- a
 * marked directive opening the file, cryptography inside it -- that four of lidgren-network-gen3's
 * platform files have.
 */
class CSharpByteOrderMarkTest extends TestBase {

    private int seen = 0;

    @Test
    void test() throws Exception {
        CSharpVerifier.verify("rules/detection/CSharpByteOrderMarkTestFile.cs", this);
        // The point of this test is a file that produced nothing at all, and asserts() is only
        // called per finding -- so without this the test would pass on the very defect it pins.
        assertThat(seen).as("findings in a file opening with a marked directive").isEqualTo(1);
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull
                    DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext>
                            detectionStore,
            @Nonnull List<INode> nodes) {
        seen++;
        assertThat(findingId).isZero();
        assertThat(nodes).hasSize(1);
        assertThat(nodes.get(0).asString()).isEqualTo("SHA-1");
    }
}
