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
package com.ibm.mapper.mapper.openssl;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.collections.CipherSuiteCollection;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.List;
import org.junit.jupiter.api.Test;

class OpenSslCipherStringMapperTest {

    private final DetectionLocation location =
            new DetectionLocation("testfile", 1, 1, List.of("test"), () -> "OpenSSL");
    private final OpenSslCipherStringMapper mapper = new OpenSslCipherStringMapper();

    @Test
    void suitesNamedInTheString() {
        INode node =
                mapper.parse(
                                "ECDHE-RSA-AES256-GCM-SHA384:!aNULL:HIGH:@SECLEVEL=2,"
                                        + " TLS_AES_128_GCM_SHA256",
                                location)
                        .orElseThrow();
        assertThat(node).isInstanceOf(CipherSuiteCollection.class);
        assertThat(((CipherSuiteCollection) node).getCollection())
                .extracting(INode::asString)
                .containsExactly("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "TLS_AES_128_GCM_SHA256");
    }

    @Test
    void keywordsAndExclusionsOnly() {
        assertThat(mapper.parse("HIGH:!aNULL:-MD5:+RC4", location)).isEmpty();
        assertThat(mapper.parse(null, location)).isEmpty();
    }
}
