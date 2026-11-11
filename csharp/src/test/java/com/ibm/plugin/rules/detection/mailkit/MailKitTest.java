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
package com.ibm.plugin.rules.detection.mailkit;

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
 * MailKit states TLS with a {@code SecureSocketOptions} argument, and in code that uses the library
 * that is the only place it is written.
 *
 * <p>Only the two members that guarantee TLS are reported. The counter-checks are the greater part
 * of this fixture on purpose: the rule matches {@code Connect} on any receiver, because the client
 * is held in a variable, so what keeps it quiet is that nothing but a member of that enum can
 * produce a value. An opportunistic member, a decision taken from a parameter, an unrelated socket
 * connect and a {@code bool} written in the same position all have to stay silent.
 */
class MailKitTest extends TestBase {

    private final List<String> found = new ArrayList<>();

    @Test
    void test() throws Exception {
        CSharpVerifier.verify("rules/detection/mailkit/MailKitTestFile.cs", this);
        assertThat(found)
                .as("TLS only where the options guarantee it")
                .containsExactly(
                        "TLS", // SslOnConnect
                        "TLS", // StartTls
                        "TLS", // the socket-taking overload: the options sit one position later
                        "TLS"); // keyword arguments out of order
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull
                    DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext>
                            detectionStore,
            @Nonnull List<INode> nodes) {
        // A detection whose value the translator declines -- an opportunistic or disabled
        // option -- arrives here with no nodes at all, and contributes nothing.
        nodes.forEach(node -> found.add(node.asString()));
    }
}
