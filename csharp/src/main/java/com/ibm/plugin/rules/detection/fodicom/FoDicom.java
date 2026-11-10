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
package com.ibm.plugin.rules.detection.fodicom;

import com.ibm.engine.detection.MethodMatcher;
import com.ibm.engine.language.csharp.tree.CSharpTree;
import com.ibm.engine.model.context.ProtocolContext;
import com.ibm.engine.model.factory.BooleanFactory;
import com.ibm.engine.model.factory.ProtocolFactory;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.DetectionRuleSet;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import java.util.List;
import java.util.Map;
import javax.annotation.Nonnull;

/**
 * Detection rules for fo-dicom, the most used DICOM library for .NET.
 *
 * <p>DICOM is a network protocol before it is a file format, and what a bill of materials wants to
 * know about a DICOM connection is whether it is protected at all. fo-dicom answers that in the
 * call itself: {@code DicomClientFactory.Create(host, port, useTls, callingAe, calledAe)} takes the
 * decision as a {@code bool}, and the sibling overload takes an {@code ITlsInitiator} instead,
 * which exists only to start TLS. Across fo-dicom and its sample repository 75 of 77 calls write
 * that argument as a literal, so the answer is nearly always in the source.
 *
 * <p>The finding is the protocol, not an algorithm: a {@code DICOM} protocol component, with a
 * {@code TLS} protocol beneath it where the call asks for TLS. A connection made without it is
 * reported as a DICOM component with nothing beneath, which is the honest statement -- these are
 * the call sites a reader is looking for.
 *
 * <p>Both overloads are read by one rule, because two rules on {@code Create} would both match and
 * count the call twice. {@code tlsInitiator} is declared where it sits in the signature, before
 * {@code useTls}, and that is what makes the pair separable without any notion of subtyping:
 *
 * <ul>
 *   <li>Flag overload: the {@code bool} is offered to {@code tlsInitiator} first and refused,
 *       because a primitive against a name in {@code KNOWN_NAMED_TYPES} is definitely incompatible.
 *       {@code useTls} is then offered the calling AE title at its own position, refuses a string
 *       for a bool, and finds the flag as the call's only bool.
 *   <li>Initiator overload: the initiator is offered to {@code tlsInitiator} at its own position
 *       and nothing rules it out, so it binds there. {@code useTls} then finds no bool anywhere and
 *       stays empty.
 * </ul>
 *
 * <p>A non-null initiator is itself the statement -- fo-dicom's own documentation says TLS is off
 * exactly when it is null -- so the presence of an argument in that slot reports TLS, and no
 * further value is read from it. A written {@code null} resolves to no value at all and reports
 * nothing, which is the same answer. An initiator a consumer wrote themselves still binds by
 * position; only a value that cannot be a {@code bool} ever reaches this parameter.
 *
 * <p>This matters because the two cases are otherwise indistinguishable in the output: before,
 * {@code Create(host, port, tlsInitiator, ...)} and {@code Create(host, port, false, ...)} both
 * produced a bare {@code DICOM} component, and a reader would take the protected association for an
 * unprotected one.
 *
 * <p>The listening side is read the same way, from {@code DicomServerFactory.Create}: a DICOM
 * server with an {@code ITlsAcceptor} requires TLS, one without accepts plaintext associations. It
 * is the weaker of the two readings, because the server factory's overloads disagree about what
 * sits at the acceptor's position and because an injected factory is invisible to receiver matching
 * -- {@code DICOM_SERVER} says which, and why that costs recall rather than precision.
 *
 * <p>No algorithm is invented. fo-dicom's own {@code DefaultTlsInitiator} defaults to {@code
 * SslProtocols.Tls12 | SslProtocols.Tls13} and names no cipher suite anywhere, and the tags it
 * generates for DICOM's own security profile ({@code MACAlgorithm}, {@code
 * EncryptedAttributesSequence}) are dictionary entries rather than operations -- referencing one
 * says a field is read or written, not that this code computes a MAC.
 */
@SuppressWarnings("java:S1192")
public final class FoDicom extends DetectionRuleSet<CSharpTree> {

    private static final String DICOM = "DICOM";

    // DicomClientFactory.Create(host, port, useTls|ITlsInitiator, callingAe, calledAe)
    private static final IDetectionRule<CSharpTree> DICOM_CLIENT =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("DicomClientFactory", "IDicomClientFactory")
                    .forMethods("Create")
                    .shouldBeDetectedAs(new ValueActionFactory<>(DICOM))
                    .withNamedMethodParameter("host", MethodMatcher.ANY)
                    .withNamedMethodParameter("port", "int")
                    // Declared where it sits in the signature, before useTls, so that both
                    // overloads bind by position alone. See the class comment.
                    .withOptionalNamedMethodParameter("tlsInitiator", "ITlsInitiator")
                    .shouldBeDetectedAs(new ProtocolFactory<>("TLS"))
                    .asChildOfParameterWithId(-1)
                    .withOptionalNamedMethodParameter("useTls", "bool")
                    .shouldBeDetectedAs(new BooleanFactory<>())
                    .asChildOfParameterWithId(-1)
                    .withOptionalNamedMethodParameter("callingAe", "string")
                    .withOptionalNamedMethodParameter("calledAe", "string")
                    .buildForContext(new ProtocolContext(Map.of("kind", DICOM)))
                    .inBundle(() -> "FoDicom")
                    .withoutDependingDetectionRules();

    /**
     * {@code new DicomClient(host, port, tlsInitiator, callingAe, calledAe, ...)}.
     *
     * <p>The constructor the factory itself ends up calling, and the clearest statement of the two:
     * it has no flag overload at all, only the initiator, and its own documentation says "if null
     * then no TLS is enabled, otherwise the handler to initiate TLS security". There is nothing to
     * tell apart, so the initiator binds at its own position.
     *
     * <p>All nine parameters are declared although only the first three are read. The binder
     * refuses a call with more arguments than the rule declares, and this constructor is always
     * called with all nine.
     */
    private static final IDetectionRule<CSharpTree> DICOM_CLIENT_CONSTRUCTOR =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("DicomClient")
                    .forMethods("<init>")
                    .shouldBeDetectedAs(new ValueActionFactory<>(DICOM))
                    .withNamedMethodParameter("host", MethodMatcher.ANY)
                    .withNamedMethodParameter("port", "int")
                    .withOptionalNamedMethodParameter("tlsInitiator", "ITlsInitiator")
                    .shouldBeDetectedAs(new ProtocolFactory<>("TLS"))
                    .asChildOfParameterWithId(-1)
                    .withOptionalNamedMethodParameter("callingAe", "string")
                    .withOptionalNamedMethodParameter("calledAe", "string")
                    .withOptionalNamedMethodParameter("clientOptions", MethodMatcher.ANY)
                    .withOptionalNamedMethodParameter("serviceOptions", MethodMatcher.ANY)
                    .withOptionalNamedMethodParameter("loggerFactory", MethodMatcher.ANY)
                    .withOptionalNamedMethodParameter(
                            "advancedDicomClientConnectionFactory", MethodMatcher.ANY)
                    .buildForContext(new ProtocolContext(Map.of("kind", DICOM)))
                    .inBundle(() -> "FoDicom")
                    .withoutDependingDetectionRules();

    /**
     * {@code DicomServerFactory.Create<T>(port, tlsAcceptor, ...)} and its two siblings.
     *
     * <p>The listening side of the same statement, and for a bill of materials the more pointed
     * one: a DICOM server is an endpoint that accepts associations, so whether it requires TLS is a
     * property of the deployment and not of a single connection. {@code tlsAcceptor} answers it the
     * way {@code tlsInitiator} does on the client -- the parameter exists only to accept TLS
     * connections, and the factory treats a null one as plaintext.
     *
     * <p>The server factory is harder to read than the client factory, and the reason is worth
     * stating because it decides the layout below. Its three overloads do not share a parameter
     * prefix: {@code Create<T>} starts with the port, {@code Create<T>(string, int, ...)} starts
     * with the address, and {@code Create<T, TServer>} puts {@code object userState} exactly where
     * the previous one puts {@code ITlsAcceptor}. An {@code object} parameter cannot be told apart
     * from an interface parameter by type -- neither is a primitive, so {@code
     * isDefinitelyIncompatible} rules out nothing -- so whichever of the two is declared at that
     * index will claim a positional argument written there.
     *
     * <p>This rule therefore declares {@code userState} at that index, not {@code tlsAcceptor}: a
     * third positional argument is then read as the opaque state it is in one overload and silently
     * dropped in the other, which costs a TLS acceptor written positionally in the middle overload
     * and can never invent one. The acceptor is still found wherever it is unambiguous -- written
     * as {@code tlsAcceptor:}, which is how every call site in fo-dicom and its sample repository
     * writes it, or as the call's only argument of acceptor type, which is what {@code
     * KNOWN_IMPLEMENTATIONS} in {@code CSharpTypeInference} is for.
     *
     * <p>Every parameter is optional because none of them sits at a fixed index across the
     * overloads, so no single one can be demanded without rejecting a legal call: {@code
     * Create<T>(port)} would be thrown away by a required {@code port} at index 1 the moment the
     * port is a variable rather than a literal. The DICOM component does not depend on any of them
     * -- the call itself is the association.
     */
    private static final IDetectionRule<CSharpTree> DICOM_SERVER =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("DicomServerFactory", "IDicomServerFactory")
                    .forMethods("Create")
                    .shouldBeDetectedAs(new ValueActionFactory<>(DICOM))
                    .withOptionalNamedMethodParameter("ipAddress", "string")
                    .withOptionalNamedMethodParameter("port", "int")
                    // Declared before tlsAcceptor on purpose, so that a third positional
                    // argument can never be read as an acceptor. See the comment above.
                    .withOptionalNamedMethodParameter("userState", MethodMatcher.ANY)
                    .withOptionalNamedMethodParameter("tlsAcceptor", "ITlsAcceptor")
                    .shouldBeDetectedAs(new ProtocolFactory<>("TLS"))
                    .asChildOfParameterWithId(-1)
                    .withOptionalNamedMethodParameter("fallbackEncoding", MethodMatcher.ANY)
                    .withOptionalNamedMethodParameter("logger", MethodMatcher.ANY)
                    .withOptionalNamedMethodParameter("configure", MethodMatcher.ANY)
                    .buildForContext(new ProtocolContext(Map.of("kind", DICOM)))
                    .inBundle(() -> "FoDicom")
                    .withoutDependingDetectionRules();

    @Nonnull
    @Override
    protected List<IDetectionRule<CSharpTree>> buildRules() {
        return List.of(DICOM_CLIENT, DICOM_CLIENT_CONSTRUCTOR, DICOM_SERVER);
    }
}
