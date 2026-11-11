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
package com.ibm.plugin.rules.detection.dotnet;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.language.csharp.CSharpCheck;
import com.ibm.engine.language.csharp.CSharpScanContext;
import com.ibm.engine.language.csharp.CSharpSymbol;
import com.ibm.engine.language.csharp.tree.CSharpTree;
import com.ibm.mapper.model.INode;
import com.ibm.plugin.CSharpVerifier;
import com.ibm.plugin.TestBase;
import java.util.ArrayList;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;

/**
 * An integer written in hex or binary is an integer.
 *
 * <p>The C# lexer has three integer tokens and the converter classified only {@code
 * INTEGER_LITERAL} as one, so a hex or binary literal fell through to the string branch and a key
 * size written as {@code 0x100} was silently lost. The parsing side already handled every base;
 * only the classification was wrong. The last case is the counter-check that a size which is not a
 * literal at all still stays unknown, in any base.
 */
class DotNetHexLiteralTest extends TestBase {

    private final List<String> found = new ArrayList<>();

    @Test
    void test() throws Exception {
        CSharpVerifier.verify("rules/detection/dotnet/DotNetHexLiteralTestFile.cs", this);
        assertThat(found)
                .as("the same key length, whatever base it was written in")
                .containsExactly(
                        // 256 -- the control case
                        "BlockCipher=AES-256[BlockSize=128, KeyLength=256,"
                                + " Oid=2.16.840.1.101.3.4.1.4]",
                        // 0x100 -- the same size, and the case that was lost before the fix
                        "BlockCipher=AES-256[BlockSize=128, KeyLength=256,"
                                + " Oid=2.16.840.1.101.3.4.1.4]",
                        // 0XC0 -- upper-case prefix and digits
                        "BlockCipher=AES-192[BlockSize=128, KeyLength=192,"
                                + " Oid=2.16.840.1.101.3.4.1.2]",
                        // 0b1000_0000 -- binary, with the digit separator C# allows
                        "BlockCipher=AES-128[BlockSize=128, KeyLength=128,"
                                + " Oid=2.16.840.1.101.3.4.1]",
                        // From a parameter: no KeyLength child, and none invented
                        "BlockCipher=AES[BlockSize=128, Oid=2.16.840.1.101.3.4.1]");
    }

    /** Renders a node and its children as {@code Kind=value[children]}, children sorted. */
    private static String render(@Nonnull INode node) {
        String self = node.getKind().getSimpleName() + "=" + node.asString();
        List<String> children =
                node.getChildren().values().stream()
                        .map(DotNetHexLiteralTest::render)
                        .sorted()
                        .toList();
        return children.isEmpty() ? self : self + children;
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull
                    DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext>
                            detectionStore,
            @Nonnull List<INode> nodes) {
        nodes.forEach(node -> found.add(render(node)));
    }
}
