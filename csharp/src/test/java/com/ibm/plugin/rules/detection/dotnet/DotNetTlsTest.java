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

/** The TLS versions a .NET service states, in the shapes real code writes them. */
class DotNetTlsTest extends TestBase {

    private final List<String> found = new ArrayList<>();

    @Test
    void test() throws Exception {
        CSharpVerifier.verify("rules/detection/dotnet/DotNetTlsTestFile.cs", this);
        assertThat(found)
                .as("every TLS version a .NET service states, and nothing it does not")
                .containsExactly(
                        // SslProtocols.None lets the platform choose, so TLS without a version is
                        // the whole of what is known.
                        "Zeile 18  TLS=TLS",
                        // A flags combination is a set: both versions are offered, not a number.
                        "Zeile 25  TLS=TLSv1.2[Version=1.2]",
                        "Zeile 25  TLS=TLSv1.3[Version=1.3]",
                        "Zeile 31  TLS=TLSv1.2[Version=1.2]",
                        "Zeile 37  TLS=TLSv1.2[Version=1.2]",
                        // fo-dicom's handler, and the association it is handed to on the next
                        // line. The two rule sets meet here.
                        "Zeile 43  TLS=TLSv1.3[Version=1.3]",
                        "Zeile 44  Protocol=DICOM[TLS=TLS]",
                        "Zeile 50  TLS=TLSv1.2[Version=1.2]",
                        // SSL 3.0 is not TLS, so it keeps its own name instead of becoming a
                        // nameless TLS -- a reader has to see what was actually offered.
                        "Zeile 56  Protocol=SSLv3",
                        "Zeile 62  TLS=TLSv1.2[Version=1.2]",
                        // The options overload names no version at the call, so none is claimed.
                        "Zeile 68  TLS=TLS",
                        // Two counter-checks come before the last entry and must not appear at
                        // all: `EnabledSslProtocols = opts.Version` reads the versions off another
                        // object and resolves to the name "Version", and `config.Version = "1.0"`
                        // is not a protocol in the first place.
                        "Zeile 90  TLS=TLS",
                        // ASP.NET Core's server-side TLS. Every UseHttps overload means the same
                        // thing and names no version, so the call reports TLS and nothing more.
                        "Zeile 96  TLS=TLS",
                        "Zeile 101  TLS=TLS",
                        // A configuration callback: the version assigned inside the lambda is
                        // reported before the UseHttps that carries it, in both lambda forms. The
                        // expression-bodied one used to produce nothing at all -- an assignment of
                        // a constant contains no call site to fall back on.
                        "Zeile 109  TLS=TLSv1.3[Version=1.3]",
                        "Zeile 107  TLS=TLS",
                        "Zeile 116  TLS=TLSv1.2[Version=1.2]",
                        "Zeile 116  TLS=TLS");
    }

    private static String render(@Nonnull INode node) {
        String self = node.getKind().getSimpleName() + "=" + node.asString();
        List<String> children =
                node.getChildren().values().stream().map(DotNetTlsTest::render).sorted().toList();
        return children.isEmpty() ? self : self + children;
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull
                    DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext>
                            detectionStore,
            @Nonnull List<INode> nodes) {
        nodes.forEach(
                node ->
                        found.add(
                                (node instanceof com.ibm.mapper.model.Protocol p
                                                ? "Zeile " + p.getDetectionContext().lineNumber()
                                                : "Zeile ?")
                                        + "  "
                                        + render(node)));
    }
}
