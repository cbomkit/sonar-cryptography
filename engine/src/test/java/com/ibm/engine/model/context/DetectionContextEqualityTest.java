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
package com.ibm.engine.model.context;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;

class DetectionContextEqualityTest {

    @Test
    void sameClassAndSamePropertiesAreEqual() {
        DigestContext one = new DigestContext(Map.of("kind", "MGF1"));
        DigestContext two = new DigestContext(Map.of("kind", "MGF1"));
        assertThat(one).isEqualTo(two).hasSameHashCodeAs(two);
    }

    @Test
    void differentPropertiesAreNotEqual() {
        assertThat(new DigestContext(Map.of("kind", "MGF1")))
                .isNotEqualTo(new DigestContext(Map.of("kind", "SHA")));
    }

    @Test
    void differentClassesWithTheSamePropertiesAreNotEqual() {
        assertThat(new DigestContext(Map.of("kind", "X")))
                .isNotEqualTo(new CipherContext(Map.of("kind", "X")));
    }

    @Test
    void keySubclassesAreNotEqualToEachOther() {
        assertThat(new PublicKeyContext(Map.of())).isNotEqualTo(new PrivateKeyContext(Map.of()));
    }

    @Test
    void keyContextsDifferingOnlyByKindAreNotEqual() {
        assertThat(new KeyContext(KeyContext.Kind.EC))
                .isNotEqualTo(new KeyContext(KeyContext.Kind.DH));
    }

    @Test
    void keyContextsWithTheSameKindAndPropertiesAreEqual() {
        assertThat(new KeyContext(KeyContext.Kind.EC))
                .isEqualTo(new KeyContext(KeyContext.Kind.EC))
                .hasSameHashCodeAs(new KeyContext(KeyContext.Kind.EC));
    }

    @Test
    void signatureContextsDifferingOnlyByKindAreNotEqual() {
        assertThat(new SignatureContext(SignatureContext.Kind.PSS))
                .isNotEqualTo(new SignatureContext(SignatureContext.Kind.MGF1));
    }

    @Test
    void protocolContextsCompareByKind() {
        assertThat(new ProtocolContext(ProtocolContext.Kind.TLS))
                .isEqualTo(new ProtocolContext(ProtocolContext.Kind.TLS))
                .isNotEqualTo(new ProtocolContext(ProtocolContext.Kind.NONE));
    }

    @Test
    void statelessContextsAreEqualToTheirOwnKind() {
        assertThat(new PRNGContext())
                .isEqualTo(new PRNGContext())
                .isNotEqualTo(new DigestContext());
    }

    @Test
    void mutatingTheSourceMapDoesNotChangeTheContext() {
        Map<String, String> source = new HashMap<>();
        source.put("kind", "MGF1");
        DigestContext context = new DigestContext(source);
        DigestContext reference = new DigestContext(Map.of("kind", "MGF1"));

        source.put("kind", "CHANGED");

        assertThat(context).isEqualTo(reference);
    }
}
