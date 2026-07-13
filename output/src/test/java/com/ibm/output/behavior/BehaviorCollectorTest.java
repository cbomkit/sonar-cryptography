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
package com.ibm.output.behavior;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.rule.IBundle;
import com.ibm.mapper.model.ContextualEvidence;
import com.ibm.mapper.model.algorithms.AES;
import com.ibm.mapper.model.algorithms.HMAC;
import com.ibm.mapper.model.functionality.Encrypt;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.Collections;
import org.junit.jupiter.api.Test;

class BehaviorCollectorTest {

    private final IBundle bundle = () -> "Test";
    private final DetectionLocation loc =
            new DetectionLocation("test.java", 1, 1, Collections.emptyList(), bundle);
    private final BehaviorCollector collector = new BehaviorCollector();

    @Test
    void macAloneYieldsIntegrityButNotAuthenticates() {
        collector.observe(new HMAC(loc));
        assertThat(collector.inferBehaviors()).containsOnly(CryptoBehavior.ENSURES_INTEGRITY);
    }

    @Test
    void macPlusJwtEvidenceAuthenticatesAndValidatesToken() {
        collector.observe(new HMAC(loc));
        collector.observe(new ContextualEvidence("JWT", loc));
        assertThat(collector.inferBehaviors())
                .containsOnly(
                        CryptoBehavior.AUTHENTICATES,
                        CryptoBehavior.VALIDATES_TOKEN,
                        CryptoBehavior.ENSURES_INTEGRITY);
    }

    @Test
    void jwtEvidenceAloneYieldsTokenBehaviors() {
        collector.observe(new ContextualEvidence("JWT", loc));
        assertThat(collector.inferBehaviors())
                .containsOnly(CryptoBehavior.AUTHENTICATES, CryptoBehavior.VALIDATES_TOKEN);
    }

    @Test
    void unknownEvidenceIdentifierIsIgnored() {
        collector.observe(new ContextualEvidence("NOT_A_KIND", loc));
        assertThat(collector.inferBehaviors()).isEmpty();
    }

    @Test
    void noneKindEvidenceIsNotAPrimary() {
        collector.observe(new ContextualEvidence("NONE", loc));
        assertThat(collector.inferBehaviors()).isEmpty();
    }

    @Test
    void nonAssetNodesAreIgnored() {
        collector.observe(new Encrypt(loc));
        assertThat(collector.inferBehaviors()).isEmpty();
    }

    @Test
    void cryptoOnlyPassesThrough() {
        final AES aes = new AES(loc);
        aes.put(new Encrypt(loc));
        collector.observe(aes);
        assertThat(collector.inferBehaviors())
                .containsOnly(CryptoBehavior.ENCRYPTS_DATA, CryptoBehavior.ENSURES_CONFIDENTIALITY);
    }
}
