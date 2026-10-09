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
package com.ibm.mapper.reorganizer.rules;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

import com.ibm.mapper.model.CipherSuite;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.Version;
import com.ibm.mapper.model.collections.CipherSuiteCollection;
import com.ibm.mapper.model.protocol.TLS;
import com.ibm.mapper.reorganizer.IReorganizerRule;
import com.ibm.mapper.reorganizer.Reorganizer;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

class CipherSuiteReorganizerTest {

    private final DetectionLocation location = mock(DetectionLocation.class);

    @Test
    void cipherSuitesWithoutProtocolAreTheSuitesOfATlsProtocol() {
        final IReorganizerRule rule =
                CipherSuiteReorganizer.ADD_TLS_PROTOCOL_AS_PARENT_OF_CIPHER_SUITES;
        final CipherSuiteCollection suites = suites("TLS_AES_128_GCM_SHA256");
        final List<INode> roots = new ArrayList<>(List.of(suites));

        assertThat(rule.match(suites, null, roots)).isTrue();
        final List<INode> result = rule.applyReorganization(suites, null, roots);

        assertThat(result).singleElement().isInstanceOf(TLS.class);
        assertThat(result.get(0).getChildren().get(CipherSuiteCollection.class)).isSameAs(suites);
    }

    @Test
    void cipherSuitesOfAProtocolAreLeftWithIt() {
        final IReorganizerRule rule =
                CipherSuiteReorganizer.ADD_TLS_PROTOCOL_AS_PARENT_OF_CIPHER_SUITES;
        final CipherSuiteCollection suites = suites("TLS_AES_128_GCM_SHA256");
        final TLS tls = new TLS(location);
        tls.put(suites);

        assertThat(rule.match(suites, tls, List.of(tls))).isFalse();
    }

    @Test
    void versionedChildReplacesTheProtocolWithItsOtherChildren() {
        final IReorganizerRule rule = CipherSuiteReorganizer.REPLACE_TLS_WITH_VERSIONED_CHILD;
        final TLS tls = new TLS(location);
        tls.put(suites("TLS_AES_128_GCM_SHA256"));
        tls.put(tls("1.2"));
        final List<INode> roots = new ArrayList<>(List.of(tls));

        assertThat(rule.match(tls, null, roots)).isTrue();
        final List<INode> result = rule.applyReorganization(tls, null, roots);

        assertThat(result).singleElement().extracting(INode::asString).isEqualTo("TLSv1.2");
        assertThat(result.get(0).hasChildOfType(CipherSuiteCollection.class)).isPresent();
        assertThat(result.get(0).getChildren().get(Version.class).asString()).isEqualTo("1.2");
    }

    @Test
    void equalProtocolsOfDifferentTreesAreEachReplacedByTheirVersionedChild() {
        // a version range gives a copy of the protocol per version
        final TLS minimum = new TLS(location);
        minimum.put(tls("1.2"));
        final TLS maximum = new TLS(location);
        maximum.put(tls("1.3"));
        assertThat(minimum).isEqualTo(maximum);

        final List<INode> result =
                new Reorganizer(List.of(CipherSuiteReorganizer.REPLACE_TLS_WITH_VERSIONED_CHILD))
                        .reorganize(new ArrayList<>(List.of(minimum, maximum)));

        assertThat(result).extracting(INode::asString).containsExactly("TLSv1.2", "TLSv1.3");
    }

    private TLS tls(String version) {
        return new TLS("TLSv" + version, new Version(version, location));
    }

    private CipherSuiteCollection suites(String name) {
        return new CipherSuiteCollection(List.of(new CipherSuite(name, location)));
    }
}
