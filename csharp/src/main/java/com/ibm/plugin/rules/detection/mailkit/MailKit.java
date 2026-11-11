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

import com.ibm.engine.detection.MethodMatcher;
import com.ibm.engine.language.csharp.tree.CSharpTree;
import com.ibm.engine.model.context.ProtocolContext;
import com.ibm.engine.model.factory.ProtocolFactory;
import com.ibm.engine.rule.DetectionRuleSet;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import java.util.List;
import java.util.Map;
import javax.annotation.Nonnull;

/**
 * How a MailKit client asks for transport security.
 *
 * <p>MailKit is the .NET mail library, and the TLS decision is not made with .NET's own API: it is
 * the {@code SecureSocketOptions} argument of {@code Connect}. That matters because the framework
 * rules in {@code DotNetTls} only see MailKit's own {@code SslStream} handshakes, which live inside
 * the library. An application that *uses* MailKit contains no handshake and no {@code SslProtocols}
 * anywhere -- just {@code client.Connect(host, 993, SecureSocketOptions.SslOnConnect)} -- so
 * without this rule its mail traffic is invisible in the bill of materials.
 *
 * <p>Only two of the five members are reported, and the reason is the difference between a decision
 * and a preference. {@code SslOnConnect} and {@code StartTls} guarantee TLS: MailKit fails the
 * connection rather than continue without it. {@code Auto} and {@code StartTlsWhenAvailable}
 * continue in plaintext when the server does not offer TLS, so whether any cryptography happens is
 * not knowable from the call, and {@code None} states that none does. The mapping lives in {@code
 * CSharpProtocolContextTranslator}, where the closed member set is also what keeps this rule quiet
 * on every unrelated {@code Connect} in a code base.
 *
 * <p>The receiver is {@code ANY}, which it has to be: the client is held in a variable and the C#
 * frontend matches a receiver by its text, not by a variable's declared type. {@code Connect} is
 * about the most common method name there is, so nothing here may state anything from a call's
 * shape alone -- there is no action on the method and no flag is read. The one value this rule can
 * produce is a name that resolves to a member of {@code SecureSocketOptions}, and that is also why
 * MailKit's obsolete {@code Connect(host, port, useSsl)} overload is deliberately not read: a
 * {@code bool} at that position cannot be told from the second argument of any other {@code
 * Connect} in the world.
 */
public final class MailKit extends DetectionRuleSet<CSharpTree> {

    private static final String SECURE_SOCKET_OPTIONS = "SecureSocketOptions";

    /**
     * {@code Connect(host, port, options, ct)} and its socket- and stream-taking siblings, plus the
     * {@code ...Async} spellings of all three.
     *
     * <p>{@code options} is declared at index 2, where the {@code (string, int, ...)} overload puts
     * it. In the {@code (Socket, string, int, ...)} and {@code (Stream, string, int, ...)}
     * overloads it sits one later, and it still binds: the port refuses it there because an {@code
     * int} can never be a {@code SecureSocketOptions}, and it is then the call's only argument of
     * that type.
     */
    private static final IDetectionRule<CSharpTree> CONNECT =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("Connect", "ConnectAsync")
                    .withOptionalNamedMethodParameter("host", MethodMatcher.ANY)
                    .withOptionalNamedMethodParameter("port", "int")
                    .withOptionalNamedMethodParameter("options", SECURE_SOCKET_OPTIONS)
                    .shouldBeDetectedAs(new ProtocolFactory<>())
                    .withOptionalNamedMethodParameter("useSsl", "bool")
                    .withOptionalNamedMethodParameter("cancellationToken", MethodMatcher.ANY)
                    .buildForContext(new ProtocolContext(Map.of("kind", "MAILKIT")))
                    .inBundle(() -> "MailKit")
                    .withoutDependingDetectionRules();

    @Nonnull
    @Override
    protected List<IDetectionRule<CSharpTree>> buildRules() {
        return List.of(CONNECT);
    }
}
