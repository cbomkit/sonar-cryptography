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
package com.ibm.engine.model.context;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Map;
import org.junit.jupiter.api.Test;

class ContextTest {

    @Test
    void testProtocolContextInvariants() {
        ProtocolContext ctxTls = new ProtocolContext(ProtocolContext.Kind.TLS);
        assertThat(ctxTls.get("kind")).hasValue("TLS");

        ProtocolContext ctxNone = new ProtocolContext(ProtocolContext.Kind.NONE);
        assertThat(ctxNone.get("kind")).isEmpty();

        ProtocolContext ctxEmpty = new ProtocolContext();
        assertThat(ctxEmpty.get("kind")).isEmpty();

        ProtocolContext ctxMap = new ProtocolContext(Map.of("kind", "TLS", "foo", "bar"));
        assertThat(ctxMap.get("kind")).hasValue("TLS");
        assertThat(ctxMap.get("foo")).hasValue("bar");
        assertThat(ctxMap.type()).isEqualTo(ProtocolContext.class);
    }

    @Test
    void testKeyContextInvariants() {
        KeyContext ctxEc = new KeyContext(KeyContext.Kind.EC);
        assertThat(ctxEc.get("kind")).hasValue("EC");

        KeyContext ctxNone = new KeyContext(KeyContext.Kind.NONE);
        assertThat(ctxNone.get("kind")).isEmpty();

        KeyContext ctxEmpty = new KeyContext();
        assertThat(ctxEmpty.get("kind")).isEmpty();

        KeyContext ctxMap = new KeyContext(Map.of("kind", "DSA", "foo", "bar"));
        assertThat(ctxMap.get("kind")).hasValue("DSA");
        assertThat(ctxMap.get("foo")).hasValue("bar");
        assertThat(ctxMap.type()).isEqualTo(KeyContext.class);
    }

    @Test
    void testSignatureContextInvariants() {
        SignatureContext ctxPss = new SignatureContext(SignatureContext.Kind.PSS);
        assertThat(ctxPss.get("kind")).hasValue("PSS");

        SignatureContext ctxNone = new SignatureContext(SignatureContext.Kind.NONE);
        assertThat(ctxNone.get("kind")).isEmpty();

        SignatureContext ctxEmpty = new SignatureContext();
        assertThat(ctxEmpty.get("kind")).isEmpty();

        SignatureContext ctxMap = new SignatureContext(Map.of("kind", "MGF1", "foo", "bar"));
        assertThat(ctxMap.get("kind")).hasValue("MGF1");
        assertThat(ctxMap.get("foo")).hasValue("bar");
        assertThat(ctxMap.type()).isEqualTo(SignatureContext.class);
    }
}
