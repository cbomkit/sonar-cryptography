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
package com.ibm.plugin.rules.detection.dcm4che;

import com.ibm.engine.model.context.ProtocolContext;
import com.ibm.engine.model.factory.ProtocolFactory;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.DetectionRuleSet;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import java.util.List;
import java.util.Map;
import javax.annotation.Nonnull;
import org.sonar.plugins.java.api.tree.Tree;

/**
 * The protocol a dcm4che connection speaks.
 *
 * <p>{@link Dcm4cheConnectionTls} reads the TLS settings of a {@code Connection} -- its cipher
 * suites and its versions -- but says nothing about what runs on top of them, so a dcm4che bill of
 * materials used to read "TLS with these suites" and never name the protocol. That is half a
 * statement for a medical-imaging product, and the C# side does not have the problem: fo-dicom's
 * factories let {@code FoDicom} emit a {@code DICOM} component directly. These rules close the gap
 * on the Java side.
 *
 * <p>dcm4che offers no factory to key on. It models the DICOM network stack as objects -- {@code
 * Device} holds {@code Connection}s and {@code ApplicationEntity}s, and an association is opened
 * from an AE -- so the statement has to come from the objects themselves. Three of them say it
 * without a guess:
 *
 * <ul>
 *   <li>{@code new ApplicationEntity(aet)}. An Application Entity Title is a DICOM concept and
 *       nothing else; the class exists only to be one. It is created by both sides, so this is the
 *       one anchor that covers a pure SCP as well as an SCU, neither of which need call anything
 *       else on this list.
 *   <li>{@code ae.connect(...)}. The call that opens the association, and the closest dcm4che has
 *       to fo-dicom's {@code DicomClientFactory.Create}. All three overloads are read by one rule
 *       keyed on the receiver type, so no overload can be counted twice.
 *   <li>{@code connection.setProtocol(...)}. The only call that can say something other than DICOM,
 *       and the reason it is read: {@code Connection.Protocol} is a closed set of six members, and
 *       {@code HL7}, {@code HL7_MLLP2}, {@code SYSLOG_TLS} and {@code SYSLOG_UDP} are protocols a
 *       bill of materials should name as themselves rather than fold into DICOM. {@code SYSLOG_TLS}
 *       additionally states transport security, so it is reported with TLS beneath it.
 * </ul>
 *
 * <p>{@code Device.bindConnections()} is deliberately not read, although it is what starts a
 * listener. A {@code Device} may hold DICOM, HL7 and syslog connections at once, so binding them
 * says that something starts listening and not which protocol -- and the connections it binds are
 * each already covered by {@code setProtocol} or by the DICOM default.
 *
 * <p>The protocol of a {@code Connection} that never has {@code setProtocol} called on it is DICOM
 * by dcm4che's own default, so silence there is not an absence of information. This rule set does
 * not invent a component for it: the {@code ApplicationEntity} that connection belongs to is what
 * reports DICOM.
 */
public final class Dcm4cheDicom extends DetectionRuleSet<Tree> {

    private static final String APPLICATION_ENTITY = "org.dcm4che3.net.ApplicationEntity";
    private static final String CONNECTION = "org.dcm4che3.net.Connection";
    private static final String PROTOCOL_ENUM = "org.dcm4che3.net.Connection$Protocol";
    private static final String STRING = "java.lang.String";
    private static final String DICOM = "DICOM";
    private static final String BUNDLE = "Dcm4che";

    @Nonnull
    private static ProtocolContext context() {
        return new ProtocolContext(Map.of("kind", DICOM));
    }

    /** {@code new ApplicationEntity()} -- the AE that a device presents to the DICOM network. */
    private static final IDetectionRule<Tree> AE_DEFAULT_CONSTRUCTOR =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectExactTypes(APPLICATION_ENTITY)
                    .forConstructor()
                    .shouldBeDetectedAs(new ValueActionFactory<>(DICOM))
                    .withoutParameters()
                    .buildForContext(context())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    /** {@code new ApplicationEntity("STORESCU")} -- the same, with the AE title given. */
    private static final IDetectionRule<Tree> AE_CONSTRUCTOR =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectExactTypes(APPLICATION_ENTITY)
                    .forConstructor()
                    .shouldBeDetectedAs(new ValueActionFactory<>(DICOM))
                    .withMethodParameter(STRING)
                    .buildForContext(context())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    /**
     * {@code ae.connect(remote, rq)}, {@code ae.connect(local, remote, rq)} and {@code
     * ae.connect(remoteAe, rq)}.
     *
     * <p>One rule for all three overloads. The arity is left open and the receiver type carries the
     * match: every {@code connect} on an {@code ApplicationEntity} returns an {@code Association},
     * so there is nothing to tell apart and nothing to read out of the arguments. Three rules, one
     * per overload, would be the usual shape here -- but they would each have to name the argument
     * types, and the only thing that would buy is the risk of two of them matching one call.
     */
    private static final IDetectionRule<Tree> ASSOCIATION =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectExactTypes(APPLICATION_ENTITY)
                    .forMethods("connect")
                    .shouldBeDetectedAs(new ValueActionFactory<>(DICOM))
                    .withAnyParameters()
                    .buildForContext(context())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    /**
     * {@code connection.setProtocol(Connection.Protocol.HL7)}.
     *
     * <p>The member name is read and mapped against the enum's six members in {@code
     * JavaProtocolContextTranslator}; anything else -- a variable, a {@code valueOf(...)}, a
     * protocol read from LDAP -- resolves to no member and reports nothing.
     */
    private static final IDetectionRule<Tree> SET_PROTOCOL =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectExactTypes(CONNECTION)
                    .forMethods("setProtocol")
                    .withMethodParameter(PROTOCOL_ENUM)
                    .shouldBeDetectedAs(new ProtocolFactory<>())
                    .buildForContext(context())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    @Nonnull
    @Override
    protected List<IDetectionRule<Tree>> buildRules() {
        return List.of(AE_DEFAULT_CONSTRUCTOR, AE_CONSTRUCTOR, ASSOCIATION, SET_PROTOCOL);
    }
}
