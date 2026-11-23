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

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.rule.RuleSets;
import com.ibm.mapper.model.INode;
import com.ibm.plugin.TestBase;
import java.util.ArrayList;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;
import org.sonar.java.checks.verifier.CheckVerifier;
import org.sonar.plugins.java.api.JavaCheck;
import org.sonar.plugins.java.api.JavaFileScannerContext;
import org.sonar.plugins.java.api.semantic.Symbol;
import org.sonar.plugins.java.api.tree.Tree;

/**
 * What protocol a dcm4che connection speaks, which the TLS rules alone could not say.
 *
 * <p>The AE and the association report DICOM from the call itself. {@code setProtocol} reports the
 * member it is given, mapped against the enum's six members, and the last two cases are the
 * counter-checks that keep it to those: a protocol taken from a parameter and one read by name at
 * runtime are both unknowable, and neither may produce a component named after whatever the
 * expression happens to mention.
 */
class Dcm4cheDicomTest extends TestBase {

    private final List<String> found = new ArrayList<>();

    protected Dcm4cheDicomTest() {
        super(RuleSets.rulesOf(Dcm4cheDicom.class));
    }

    @Test
    void test() {
        // The dcm4che jars are fetched, not checked in, so a build without network access has
        // none and this test is skipped rather than asserting against an empty classpath.
        assumeTrue(Dcm4cheJars.available(), Dcm4cheJars.unavailableReason());
        CheckVerifier.newVerifier()
                .onFile("src/test/files/rules/detection/dcm4che/Dcm4cheDicomTestFile.java")
                .withChecks(this)
                .withClassPath(Dcm4cheJars.latestJars)
                .verifyIssues();
        assertThat(found)
                .as("one protocol per call, and only the enum's own members")
                .containsExactly(
                        "Protocol=DICOM", // new ApplicationEntity("STORESCU")
                        "Protocol=DICOM", // new ApplicationEntity()
                        "Protocol=DICOM", // ae.connect(remote, rq)
                        "Protocol=DICOM", // ae.connect(local, remote, rq)
                        "Protocol=DICOM", // ae.connect(remoteAe, rq)
                        "Protocol=DICOM", // setProtocol(Protocol.DICOM)
                        "Protocol=HL7", // setProtocol(Protocol.HL7)
                        "Protocol=HL7", // HL7_MLLP2 is a framing of HL7, not a protocol of its own
                        // The only member that states transport security as well. The nested TLS
                        // does not raise an issue of its own -- a node's children are keyed by kind
                        // -- but it is what reaches the bill of materials.
                        "Protocol=Syslog[TLS=TLS]",
                        "Protocol=Syslog", // SYSLOG_UDP: nothing protects it
                        "Protocol=HTTP");
    }

    /** Renders a node and its children as {@code Kind=value[children]}, children sorted. */
    private static String render(@Nonnull INode node) {
        String self = node.getKind().getSimpleName() + "=" + node.asString();
        List<String> children =
                node.getChildren().values().stream()
                        .map(Dcm4cheDicomTest::render)
                        .sorted()
                        .toList();
        return children.isEmpty() ? self : self + children;
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> detectionStore,
            @Nonnull List<INode> nodes) {
        nodes.forEach(node -> found.add(render(node)));
    }
}
