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
package com.ibm.plugin.translation.translator.contexts;

import com.ibm.engine.model.CipherSuite;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.context.DetectionContext;
import com.ibm.engine.model.context.ProtocolContext;
import com.ibm.engine.rule.IBundle;
import com.ibm.mapper.IContextTranslation;
import com.ibm.mapper.mapper.ssl.CipherSuiteMapper;
import com.ibm.mapper.mapper.ssl.SSLVersionMapper;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.Protocol;
import com.ibm.mapper.model.Unknown;
import com.ibm.mapper.model.protocol.TLS;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.Optional;
import javax.annotation.Nonnull;
import org.sonar.plugins.java.api.tree.Tree;

public final class JavaProtocolContextTranslator implements IContextTranslation<Tree> {

    @Nonnull
    @Override
    public Optional<INode> translate(
            @Nonnull IBundle bundleIdentifier,
            @Nonnull IValue<Tree> value,
            @Nonnull DetectionContext detectionContext,
            @Nonnull DetectionLocation detectionLocation) {
        // Dcm4che joins SSL here because a DICOM association is TLS underneath: its cipher suites
        // and protocol versions are the same strings the JSSE setters take, and are read by the
        // same mappers. The "kind" of the context tells the two apart below.
        if (!"SSL".equals(bundleIdentifier.getIdentifier())
                && !"Dcm4che".equals(bundleIdentifier.getIdentifier())) {
            return Optional.empty();
        }

        final String kind = ((ProtocolContext) detectionContext).get("kind").orElse("");
        if (value instanceof ValueAction<Tree> valueAction) {
            // The DICOM rules state the protocol from the call itself: an ApplicationEntity or an
            // association is DICOM, with no argument to read.
            return "DICOM".equals(kind)
                    ? Optional.of(new Protocol(valueAction.asString(), detectionLocation))
                    : Optional.empty();
        }
        if (value instanceof com.ibm.engine.model.Protocol<Tree> protocol && "DICOM".equals(kind)) {
            return dcm4cheProtocol(protocol.asString(), detectionLocation);
        }
        if (value instanceof com.ibm.engine.model.Protocol<Tree> protocol) {
            return switch (kind) {
                case "TLS" ->
                        Optional.of(protocol)
                                .map(
                                        p -> {
                                            final SSLVersionMapper sslVersionMapper =
                                                    new SSLVersionMapper();
                                            return sslVersionMapper
                                                    .parse(p.asString(), detectionLocation)
                                                    .map(TLS::new)
                                                    .orElse(new TLS(detectionLocation));
                                        });
                default ->
                        Optional.of(protocol)
                                .map(p -> new Protocol(p.asString(), detectionLocation));
            };
        } else if (value instanceof CipherSuite<Tree> cipherSuite) {
            return switch (kind) {
                case "TLS" ->
                        new CipherSuiteMapper()
                                .parse(cipherSuite.get(), detectionLocation)
                                .map(n -> n);
                default ->
                        Optional.of(cipherSuite)
                                .map(
                                        suite ->
                                                new com.ibm.mapper.model.CipherSuite(
                                                        suite.asString(), detectionLocation));
            };
        }

        return Optional.of(new Unknown(detectionLocation));
    }

    /**
     * The six members of {@code org.dcm4che3.net.Connection.Protocol}, and nothing else.
     *
     * <p>{@code setProtocol} is the only dcm4che call that can name a protocol other than DICOM, so
     * it is read by name -- and a name is only accepted when it is a member of that enum.
     * Everything else a call site can write there (a variable, {@code Protocol.valueOf(...)}, a
     * value read from LDAP) resolves to a name this does not know, and reports nothing rather than
     * a protocol component called after a field.
     *
     * <p>{@code SYSLOG_TLS} is the one member that carries more than a name: it is syslog over TLS,
     * so the TLS is reported beneath it. {@code HL7_MLLP2} is HL7 over MLLP release 2 -- a framing
     * of the same protocol, so it is reported as HL7.
     */
    @Nonnull
    private static Optional<INode> dcm4cheProtocol(
            @Nonnull String member, @Nonnull DetectionLocation detectionLocation) {
        return switch (member) {
            case "DICOM" -> Optional.of(new Protocol("DICOM", detectionLocation));
            case "HL7", "HL7_MLLP2" -> Optional.of(new Protocol("HL7", detectionLocation));
            case "SYSLOG_UDP" -> Optional.of(new Protocol("Syslog", detectionLocation));
            case "SYSLOG_TLS" -> {
                final Protocol syslog = new Protocol("Syslog", detectionLocation);
                syslog.put(new TLS(detectionLocation));
                yield Optional.of(syslog);
            }
            case "HTTP" -> Optional.of(new Protocol("HTTP", detectionLocation));
            default -> Optional.empty();
        };
    }
}
