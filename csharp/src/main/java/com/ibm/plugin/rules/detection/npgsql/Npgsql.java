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
package com.ibm.plugin.rules.detection.npgsql;

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
 * Whether a database connection requires TLS.
 *
 * <p>{@code SslMode} is how the .NET database drivers state it -- Npgsql for PostgreSQL and
 * MySqlConnector for MySQL spell the property and most of its members the same way -- and like
 * MailKit's {@code SecureSocketOptions} it is the only TLS statement that appears in code that
 * *uses* the driver. The driver's own {@code SslStream} handshake is inside the driver.
 *
 * <p>Three members require TLS and are reported: {@code Require}, and {@code VerifyCA} and {@code
 * VerifyFull}, which require it and additionally validate the certificate. {@code Prefer}, {@code
 * Allow} and MySqlConnector's {@code Preferred} fall back to plaintext when the server declines, so
 * nothing is reported for them, and {@code Disable} and {@code None} state that there is nothing to
 * report. Certificate validation itself is not recorded: CycloneDX protocol properties have no
 * field for it, which is the same reason fo-dicom's {@code RequireMutualAuthentication} is left
 * out.
 *
 * <p>Only the property assignment is read. The same setting can be written into a connection string
 * ({@code "Host=db;SslMode=Require"}), and that is deliberately not matched -- a connection string
 * is an opaque literal, and picking settings out of one by substring would report a mode that any
 * number of unrelated strings could contain.
 */
public final class Npgsql extends DetectionRuleSet<CSharpTree> {

    /** {@code builder.SslMode = SslMode.Require}, as a synthetic property setter. */
    private static final IDetectionRule<CSharpTree> SET_SSL_MODE =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("set_SslMode")
                    .withNamedMethodParameter("value", "SslMode")
                    .shouldBeDetectedAs(new ProtocolFactory<>())
                    .buildForContext(new ProtocolContext(Map.of("kind", "SSL_MODE")))
                    .inBundle(() -> "Npgsql")
                    .withoutDependingDetectionRules();

    @Nonnull
    @Override
    protected List<IDetectionRule<CSharpTree>> buildRules() {
        return List.of(SET_SSL_MODE);
    }
}
