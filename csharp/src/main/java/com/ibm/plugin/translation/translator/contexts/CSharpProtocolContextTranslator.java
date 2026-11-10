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
package com.ibm.plugin.translation.translator.contexts;

import com.ibm.engine.language.csharp.tree.CSharpTree;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.OperationMode;
import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.context.DetectionContext;
import com.ibm.engine.rule.IBundle;
import com.ibm.mapper.mapper.ssl.SSLVersionMapper;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.Protocol;
import com.ibm.mapper.model.protocol.TLS;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.Optional;
import javax.annotation.Nonnull;

/**
 * Translates the protocol findings of the medical-imaging and health-exchange rule sets.
 *
 * <p>These rule sets report a standard rather than an algorithm. DICOM and FHIR name no
 * cryptography of their own: what a bill of materials can learn from a call is which standard is
 * spoken and whether the transport beneath it is protected. Both answers are worth having -- a
 * DICOM association opened without TLS, or a FHIR client pointed at an {@code http://} endpoint, is
 * exactly the call site a reader is looking for -- and neither is an algorithm.
 *
 * <p>A protocol with nothing beneath it is a complete CycloneDX component: only {@code assetType}
 * and the protocol {@code type} are required, and the project's own {@code ProtocolTest} asserts
 * that shape for a TLS carrying only a version. This follows the precedent set on the algorithm
 * side by {@code NATIVEPRNG} and DPAPI, where the API does not expose the concrete algorithm and a
 * generic node is recorded rather than an invented specific one.
 */
public final class CSharpProtocolContextTranslator {

    /** The value {@link com.ibm.engine.model.factory.BooleanFactory} gives a {@code true}. */
    private static final int TRUE = 1;

    public Optional<INode> translate(
            @Nonnull IBundle bundleIdentifier,
            @Nonnull IValue<CSharpTree> value,
            @Nonnull DetectionContext detectionContext,
            @Nonnull DetectionLocation detectionLocation) {
        final String kind = detectionContext.get("kind").orElse("");

        if (value instanceof ValueAction<CSharpTree> valueAction) {
            // "DICOM" or "FHIR" for the call itself, "TLS" for an argument that can only mean TLS
            // -- fo-dicom's ITlsInitiator overload exists for no other purpose.
            return "TLS".equals(valueAction.asString())
                    ? Optional.of(new TLS(detectionLocation))
                    : Optional.of(new Protocol(valueAction.asString(), detectionLocation));
        }

        if (value instanceof com.ibm.engine.model.Protocol<CSharpTree> protocol) {
            // The name of an enum member, read from a property assignment or a call argument --
            // plus the constant "TLS" of fo-dicom's ITlsInitiator overload, where an initiator
            // exists for one purpose and its presence is the statement.
            //
            // Which enum it is has to be decided by the kind rather than by the name, because the
            // names collide and mean opposite things: SslProtocols.None is "let the platform
            // choose", which is TLS, while SecureSocketOptions.None is "no encryption at all".
            return switch (kind) {
                case "MAILKIT" -> secureSocketOptions(protocol.asString(), detectionLocation);
                case "SSL_MODE" -> sslMode(protocol.asString(), detectionLocation);
                default -> dotNetProtocol(protocol.asString(), detectionLocation);
            };
        }

        if (value instanceof OperationMode<CSharpTree> operationMode && !kind.isEmpty()) {
            // The useTls flag of fo-dicom's DicomClientFactory.Create. Only a true is recorded: a
            // false means the connection carries no TLS, and the absence of a TLS node under the
            // protocol already says that. There is no node for "explicitly not protected", and
            // inventing one would read as a finding of its own.
            return TRUE == operationMode.get()
                    ? Optional.of(new TLS(detectionLocation))
                    : Optional.empty();
        }

        return Optional.empty();
    }

    /**
     * The protocol a .NET name stands for, or nothing when the name is not one of them.
     *
     * <p>{@code SslProtocols} and {@code SecurityProtocolType} have a closed set of members, and
     * that set is the guard. A property assignment reaches this point with whatever name its
     * argument resolved to, and the argument is not always a member of the enum: RabbitMQ writes
     * {@code EnabledSslProtocols = opts.Version}, which resolves to the name {@code Version}
     * because that is what the member access is called. Passing such a name through would put a
     * protocol called "Version" in the bill of materials. Neither the matcher nor the argument
     * binder can rule it out -- the root of that access is a variable, not a type -- so the
     * decision belongs here, where the name itself can be checked.
     *
     * <p>{@code None}, {@code Default} and {@code SystemDefault} mean "whatever the platform picks"
     * and so state TLS without a version, which is exactly what is known. {@code Ssl2} and {@code
     * Ssl3} get a protocol of their own rather than a version: SSL is not TLS, and a reader has to
     * see what was actually offered.
     */
    @Nonnull
    private static Optional<INode> dotNetProtocol(
            @Nonnull String name, @Nonnull DetectionLocation detectionLocation) {
        return switch (name) {
            case "Tls13" -> versioned("TLSv1.3", detectionLocation);
            case "Tls12" -> versioned("TLSv1.2", detectionLocation);
            case "Tls11" -> versioned("TLSv1.1", detectionLocation);
            case "Tls" -> versioned("TLSv1.0", detectionLocation);
            case "Ssl3" -> Optional.of(new Protocol("SSLv3", detectionLocation));
            case "Ssl2" -> Optional.of(new Protocol("SSLv2", detectionLocation));
            case "TLS", "None", "Default", "SystemDefault" ->
                    Optional.of(new TLS(detectionLocation));
            default -> Optional.empty();
        };
    }

    /**
     * The member of MailKit's {@code SecureSocketOptions} that a name stands for, when it states
     * TLS.
     *
     * <p>Two of the five members are a decision and three are not. {@code SslOnConnect} negotiates
     * TLS before anything else is sent and {@code StartTls} requires the server to offer the
     * STARTTLS extension, failing the connection when it does not -- both mean TLS happened. {@code
     * Auto} and {@code StartTlsWhenAvailable} continue in plaintext against a server that offers
     * nothing, so the call does not say whether any cryptography takes place, and {@code None} says
     * that none does. CycloneDX has no component for "explicitly unprotected", and an unversioned
     * TLS would claim more than the call supports, so those three report nothing.
     *
     * <p>No version is recorded for either member. MailKit takes it from the client's own {@code
     * SslProtocols} property, which {@code DotNetTls} reads separately.
     */
    @Nonnull
    private static Optional<INode> secureSocketOptions(
            @Nonnull String name, @Nonnull DetectionLocation detectionLocation) {
        return switch (name) {
            case "SslOnConnect", "StartTls" -> Optional.of(new TLS(detectionLocation));
            default -> Optional.empty();
        };
    }

    /**
     * The member of a database driver's {@code SslMode} that a name stands for, when it requires
     * TLS.
     *
     * <p>Npgsql and MySqlConnector share the property name and most of the members. {@code Require}
     * and MySqlConnector's {@code Required} require TLS; {@code VerifyCA} and {@code VerifyFull}
     * require it and validate the certificate as well, which is not separately representable and so
     * is not recorded. {@code Prefer}, {@code Allow} and {@code Preferred} fall back to an
     * unencrypted connection when the server declines, and {@code Disable} and {@code None} ask for
     * one, so none of those five states that cryptography happens.
     */
    @Nonnull
    private static Optional<INode> sslMode(
            @Nonnull String name, @Nonnull DetectionLocation detectionLocation) {
        return switch (name) {
            case "Require", "Required", "VerifyCA", "VerifyFull" ->
                    Optional.of(new TLS(detectionLocation));
            default -> Optional.empty();
        };
    }

    @Nonnull
    private static Optional<INode> versioned(
            @Nonnull String wireName, @Nonnull DetectionLocation detectionLocation) {
        return new SSLVersionMapper()
                .parse(wireName, detectionLocation)
                .map(version -> (INode) new TLS(version));
    }
}
