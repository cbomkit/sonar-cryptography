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
import com.ibm.engine.language.IArgumentBinder;
import com.ibm.engine.language.csharp.CSharpCheck;
import com.ibm.engine.language.csharp.CSharpLanguageSupport;
import com.ibm.engine.language.csharp.CSharpScanContext;
import com.ibm.engine.language.csharp.CSharpSymbol;
import com.ibm.engine.language.csharp.tree.CSharpBlockTree;
import com.ibm.engine.language.csharp.tree.CSharpMethodInvocationTree;
import com.ibm.engine.language.csharp.tree.CSharpTree;
import com.ibm.engine.rule.DetectionRule;
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
 * is held in a variable, so what keeps it quiet is that it matches only a call with an argument
 * that can be a {@code SecureSocketOptions}, and that nothing but a member of that enum can produce
 * a value. An opportunistic member and a decision taken from a parameter have to stay silent; an
 * unrelated socket connect, a {@code Connect(host, port)} without options and a {@code bool}
 * written in the options' position must not even match.
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

    /**
     * Which {@code Connect} calls the rule matches at all, whether or not a value comes out of
     * them. The source engine reports only matches that produce a value, so {@link #test} cannot
     * see a match without one; a binary scanner reports every match, and there a value-less match
     * on every {@code Connect} of an application is noise. So the binding is checked directly: a
     * call is bound only when it carries an argument that can be the {@code SecureSocketOptions}.
     */
    @Test
    void onlyCallsWithTheOptionAreMatched() throws Exception {
        @SuppressWarnings("unchecked")
        DetectionRule<CSharpTree> connect =
                (DetectionRule<CSharpTree>) new MailKit().buildRules().get(0);
        IArgumentBinder<CSharpTree> binder =
                new CSharpLanguageSupport().namedArgumentBinder().orElseThrow();
        List<Integer> bound = new ArrayList<>();
        List<Integer> refused = new ArrayList<>();
        for (CSharpBlockTree body :
                CSharpVerifier.methodBodies("rules/detection/mailkit/MailKitTestFile.cs")) {
            for (CSharpTree statement : body.getStatements()) {
                if (statement instanceof CSharpMethodInvocationTree call
                        && call.getMethodName().startsWith("Connect")) {
                    (binder.bind(connect, call).isPresent() ? bound : refused).add(call.getLine());
                }
            }
        }
        assertThat(bound)
                .as("calls that carry a SecureSocketOptions argument")
                .containsExactly(
                        17, // SslOnConnect
                        23, // StartTls
                        29, // over a socket: the options sit one position later
                        35, // keyword arguments out of order
                        41, // None: matched, the translator declines it
                        50, // Auto: matched, the translator declines it
                        51, // StartTlsWhenAvailable: matched, the translator declines it
                        57); // from a parameter: matched, no value to resolve
        assertThat(refused)
                .as("calls without one are not matched at all")
                .containsExactly(
                        63, // socket.Connect(endPoint)
                        72, // client.Connect(host, port)
                        73, // client.ConnectAsync(host, port)
                        74, // tcpClient.Connect(host, port)
                        83); // the obsolete bool overload
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
