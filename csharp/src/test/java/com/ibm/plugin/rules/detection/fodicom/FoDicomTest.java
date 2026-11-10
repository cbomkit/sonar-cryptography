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

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.language.csharp.CSharpCheck;
import com.ibm.engine.language.csharp.CSharpScanContext;
import com.ibm.engine.language.csharp.CSharpSymbol;
import com.ibm.engine.language.csharp.tree.CSharpTree;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.protocol.TLS;
import com.ibm.plugin.CSharpVerifier;
import com.ibm.plugin.TestBase;
import java.util.ArrayList;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;

/**
 * A DICOM association is reported as the protocol it is, with TLS beneath it only where the call
 * says so.
 *
 * <p>The fixture is modelled on fo-dicom's sample repository, where the transport decision is
 * written as a literal in 75 of 77 calls. Both overloads of {@code Create} state it: the flag
 * directly, and the {@code ITlsInitiator} by being there at all, since fo-dicom's documentation
 * says TLS is off exactly when the initiator is null.
 *
 * <p>Two counter-checks guard the slot from either side. A written {@code null} must not read as
 * TLS, and a decision that arrives as a method parameter is not knowable, so that connection is
 * reported as DICOM with nothing beneath rather than as either secured or unsecured. The flag cases
 * also prove the calling AE title never slides into the initiator slot: were it to, every unsecured
 * association in the fixture would read as TLS.
 */
class FoDicomTest extends TestBase {

    private final List<String> found = new ArrayList<>();

    @Test
    void test() throws Exception {
        CSharpVerifier.verify("rules/detection/fodicom/FoDicomTestFile.cs", this);
        assertThat(found)
                .as("one protocol per association, TLS only where the call states it")
                .containsExactly(
                        "DICOM", // Create(..., false, ...)
                        "DICOM+TLS", // Create(..., true, ...)
                        "DICOM", // host and AE titles from fields, useTls still false
                        "DICOM+TLS", // the ITlsInitiator overload
                        "DICOM+TLS", // a DefaultTlsInitiator held in a var
                        "DICOM+TLS", // a DefaultTlsInitiator constructed in the argument
                        "DICOM+TLS", // a consumer's own ITlsInitiator implementation
                        "DICOM", // a written null: fo-dicom reads that as TLS off
                        "DICOM+TLS", // keyword arguments out of order
                        "DICOM+TLS", // new DicomClient(...) with an initiator
                        "DICOM", // new DicomClient(...) with a written null
                        "DICOM", // useTls is a method parameter: nothing invented
                        // The listening side.
                        "DICOM", // a server on the plaintext port
                        "DICOM", // the port from a field, so no parameter may be demanded
                        "DICOM+TLS", // tlsAcceptor: as a keyword, past a keyword logger
                        "DICOM+TLS", // a DefaultTlsAcceptor built in the argument
                        // No entry for the injected-factory call: a receiver held in a variable is
                        // matched by its text, not its declared type, so that call site yields
                        // nothing. The fixture says why.
                        "DICOM", // named user state is not an acceptor
                        "DICOM", // positional user state where a sibling overload puts the acceptor
                        "DICOM"); // a written null acceptor means plaintext
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull
                    DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext>
                            detectionStore,
            @Nonnull List<INode> nodes) {
        assertThat(nodes).hasSize(1);
        final INode node = nodes.get(0);
        found.add(node.asString() + (node.hasChildOfType(TLS.class).isPresent() ? "+TLS" : ""));
    }
}
