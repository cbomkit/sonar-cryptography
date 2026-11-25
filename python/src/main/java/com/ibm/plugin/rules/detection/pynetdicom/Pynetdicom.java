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
package com.ibm.plugin.rules.detection.pynetdicom;

import com.ibm.engine.detection.MethodMatcher;
import com.ibm.engine.model.context.ProtocolContext;
import com.ibm.engine.model.factory.ProtocolFactory;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.DetectionRuleSet;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import java.util.List;
import java.util.Map;
import javax.annotation.Nonnull;
import org.sonar.plugins.python.api.tree.Tree;

/**
 * Detection rules for pynetdicom, the DICOM networking library for Python.
 *
 * <p>DICOM is a network protocol before it is a file format, and what a bill of materials wants to
 * know about a DICOM connection is whether it is protected. pynetdicom answers that in the call
 * itself, and only there:
 *
 * <ul>
 *   <li>{@code AE.associate(addr, port, ..., tls_args=(ssl_context, hostname))} opens an
 *       association as a client; TLS is on exactly when {@code tls_args} is given.
 *   <li>{@code AE.start_server(address, ..., ssl_context=ctx)} and {@code AE.make_server(address,
 *       ..., ssl_context=ctx)} listen as a server; TLS is on exactly when {@code ssl_context} is
 *       given.
 * </ul>
 *
 * <p>The finding is the protocol, not an algorithm: a {@code DICOM} protocol component, with a
 * {@code TLS} protocol beneath it where the call hands over a TLS configuration. A call without it
 * is reported as DICOM with nothing beneath, which are the call sites a reader is looking for. TLS
 * is only reported when the argument certainly is an object (a call, a tuple, or a local bound once
 * to one); {@code None}, parameters and attributes may be None and report nothing. No version or
 * cipher suite is invented -- they are configured on the {@code ssl.SSLContext}, not in these
 * calls.
 *
 * <p>pydicom has no cryptography to detect: it reads and writes datasets, and the DICOM security
 * profile tags it exposes ({@code MACAlgorithm}, {@code EncryptedAttributesSequence}) are
 * dictionary entries rather than operations. Its only hash, {@code generate_uid(entropy_srcs=...)},
 * derives an identifier rather than protecting anything and is deliberately not reported.
 */
@SuppressWarnings("java:S1192")
public final class Pynetdicom extends DetectionRuleSet<Tree> {

    private static final String[] AE_TYPES = {
        "pynetdicom.AE", "pynetdicom.ae.AE", "pynetdicom.ae.ApplicationEntity"
    };
    private static final String DICOM = "DICOM";
    private static final String TLS = "TLS";

    // AE.associate(addr, port, contexts, ae_title, max_pdu, ext_neg, bind_address, tls_args,
    // evt_handlers)
    private static final IDetectionRule<Tree> ASSOCIATE =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(AE_TYPES)
                    .forMethods("associate")
                    .shouldBeDetectedAs(new ValueActionFactory<>(DICOM))
                    .withNamedMethodParameter("addr", MethodMatcher.ANY)
                    .withNamedMethodParameter("port", MethodMatcher.ANY)
                    .withOptionalNamedMethodParameter("contexts", MethodMatcher.ANY)
                    .withOptionalNamedMethodParameter("ae_title", MethodMatcher.ANY)
                    .withOptionalNamedMethodParameter("max_pdu", MethodMatcher.ANY)
                    .withOptionalNamedMethodParameter("ext_neg", MethodMatcher.ANY)
                    .withOptionalNamedMethodParameter("bind_address", MethodMatcher.ANY)
                    .withOptionalNamedMethodParameter("tls_args", MethodMatcher.ANY)
                    .shouldBeDetectedAs(new ProtocolFactory<>(TLS))
                    .asChildOfParameterWithId(-1)
                    .withOptionalNamedMethodParameter("evt_handlers", MethodMatcher.ANY)
                    .buildForContext(new ProtocolContext(Map.of("kind", DICOM)))
                    .inBundle(() -> "Pynetdicom")
                    .withoutDependingDetectionRules();

    // AE.start_server(address, block, ssl_context, evt_handlers, ae_title, contexts)
    private static final IDetectionRule<Tree> START_SERVER =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(AE_TYPES)
                    .forMethods("start_server")
                    .shouldBeDetectedAs(new ValueActionFactory<>(DICOM))
                    .withNamedMethodParameter("address", MethodMatcher.ANY)
                    .withOptionalNamedMethodParameter("block", MethodMatcher.ANY)
                    .withOptionalNamedMethodParameter("ssl_context", MethodMatcher.ANY)
                    .shouldBeDetectedAs(new ProtocolFactory<>(TLS))
                    .asChildOfParameterWithId(-1)
                    .withOptionalNamedMethodParameter("evt_handlers", MethodMatcher.ANY)
                    .withOptionalNamedMethodParameter("ae_title", MethodMatcher.ANY)
                    .withOptionalNamedMethodParameter("contexts", MethodMatcher.ANY)
                    .buildForContext(new ProtocolContext(Map.of("kind", DICOM)))
                    .inBundle(() -> "Pynetdicom")
                    .withoutDependingDetectionRules();

    // AE.make_server(address, ae_title, contexts, ssl_context, evt_handlers, server_class)
    private static final IDetectionRule<Tree> MAKE_SERVER =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(AE_TYPES)
                    .forMethods("make_server")
                    .shouldBeDetectedAs(new ValueActionFactory<>(DICOM))
                    .withNamedMethodParameter("address", MethodMatcher.ANY)
                    .withOptionalNamedMethodParameter("ae_title", MethodMatcher.ANY)
                    .withOptionalNamedMethodParameter("contexts", MethodMatcher.ANY)
                    .withOptionalNamedMethodParameter("ssl_context", MethodMatcher.ANY)
                    .shouldBeDetectedAs(new ProtocolFactory<>(TLS))
                    .asChildOfParameterWithId(-1)
                    .withOptionalNamedMethodParameter("evt_handlers", MethodMatcher.ANY)
                    .withOptionalNamedMethodParameter("server_class", MethodMatcher.ANY)
                    .buildForContext(new ProtocolContext(Map.of("kind", DICOM)))
                    .inBundle(() -> "Pynetdicom")
                    .withoutDependingDetectionRules();

    @Nonnull
    @Override
    protected List<IDetectionRule<Tree>> buildRules() {
        return List.of(ASSOCIATE, START_SERVER, MAKE_SERVER);
    }
}
