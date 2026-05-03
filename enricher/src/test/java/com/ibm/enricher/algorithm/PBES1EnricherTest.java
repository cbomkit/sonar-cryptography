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
package com.ibm.enricher.algorithm;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.enricher.TestBase;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.Oid;
import com.ibm.mapper.model.PBES1;
import com.ibm.mapper.model.algorithms.DES;
import com.ibm.mapper.model.algorithms.MD5;
import com.ibm.mapper.model.algorithms.SHA;
import com.ibm.mapper.model.algorithms.TripleDES;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.List;
import org.junit.jupiter.api.Test;

class PBES1EnricherTest extends TestBase {

    @Test
    void pkcs5() {
        DetectionLocation testDetectionLocation =
                new DetectionLocation("testfile", 1, 1, List.of("test"), () -> "Jca");
        final PBES1 pbes1 =
                new PBES1(new MD5(testDetectionLocation), new DES(testDetectionLocation));
        this.logBefore(pbes1);

        final PBES1Enricher pbes1Enricher = new PBES1Enricher();
        final INode enriched = pbes1Enricher.enrich(pbes1);
        this.logAfter(enriched);

        assertThat(enriched.hasChildOfType(Oid.class)).isPresent();
        assertThat(enriched.hasChildOfType(Oid.class).get().asString())
                .isEqualTo("1.2.840.113549.1.5.3");
    }

    @Test
    void pkcs12() {
        DetectionLocation testDetectionLocation =
                new DetectionLocation("testfile", 1, 1, List.of("test"), () -> "Jca");
        final PBES1 pbes1 =
                new PBES1(
                        new SHA(testDetectionLocation), new TripleDES(192, testDetectionLocation));
        this.logBefore(pbes1);

        final PBES1Enricher pbes1Enricher = new PBES1Enricher();
        final INode enriched = pbes1Enricher.enrich(pbes1);
        this.logAfter(enriched);

        assertThat(enriched.hasChildOfType(Oid.class)).isPresent();
        assertThat(enriched.hasChildOfType(Oid.class).get().asString())
                .isEqualTo("1.2.840.113549.1.12.1.3");
    }
}
