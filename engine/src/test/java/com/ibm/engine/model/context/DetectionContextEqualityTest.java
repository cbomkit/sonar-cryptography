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
                .isEqualTo(new KeyContext(Map.of("kind", "EC")))
                .hasSameHashCodeAs(new KeyContext(Map.of("kind", "EC")));
        assertThat(new KeyContext(Map.of("kind", "EC")).kind()).isEqualTo(KeyContext.Kind.EC);
        assertThat(new PrivateKeyContext(KeyContext.Kind.EC))
                .isEqualTo(new PrivateKeyContext(Map.of("kind", "EC")));
    }

    @Test
    void signatureContextsDifferingOnlyByKindAreNotEqual() {
        assertThat(new SignatureContext(SignatureContext.Kind.PSS))
                .isNotEqualTo(new SignatureContext(SignatureContext.Kind.MGF1));
        assertThat(new SignatureContext(SignatureContext.Kind.PSS))
                .isEqualTo(new SignatureContext(Map.of("kind", "PSS")));
        assertThat(new SignatureContext(Map.of("kind", "PSS")).kind())
                .isEqualTo(SignatureContext.Kind.PSS);
    }

    @Test
    void protocolContextsCompareByKind() {
        assertThat(new ProtocolContext(ProtocolContext.Kind.TLS))
                .isEqualTo(new ProtocolContext(ProtocolContext.Kind.TLS))
                .isEqualTo(new ProtocolContext(Map.of("kind", "TLS")))
                .isNotEqualTo(new ProtocolContext(ProtocolContext.Kind.NONE));
        assertThat(new ProtocolContext(Map.of("kind", "TLS")).kind())
                .isEqualTo(ProtocolContext.Kind.TLS);
    }

    @Test
    void noneKindUsesTheDefaultRepresentation() {
        assertThat(new KeyContext(KeyContext.Kind.NONE))
                .isEqualTo(new KeyContext())
                .isEqualTo(new KeyContext(Map.of("kind", "NONE")));
        assertThat(new SignatureContext(SignatureContext.Kind.NONE))
                .isEqualTo(new SignatureContext())
                .isEqualTo(new SignatureContext(Map.of("kind", "NONE")));
        assertThat(new ProtocolContext(ProtocolContext.Kind.NONE))
                .isEqualTo(new ProtocolContext())
                .isEqualTo(new ProtocolContext(Map.of("kind", "NONE")));
    }

    @Test
    void customKindValuesRemainInTheMap() {
        KeyContext context = new KeyContext(Map.of("kind", "MLDSA"));
        assertThat(context.get("kind")).contains("MLDSA");
        assertThat(context.kind()).isEqualTo(KeyContext.Kind.NONE);
        assertThat(context).isNotEqualTo(new KeyContext());
    }

    @Test
    void statelessContextsAreEqualToTheirOwnKind() {
        assertThat(new PRNGContext())
                .isEqualTo(new PRNGContext())
                .isNotEqualTo(new DigestContext());
        assertThat(new PRNGContext(Map.of("kind", "secure")))
                .isNotEqualTo(new PRNGContext())
                .isEqualTo(new PRNGContext(Map.of("kind", "secure")));
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
