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
package com.ibm.mapper.mapper.jca;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.Test;

class JcaMessageDigestMapperTest {

    @Test
    void base() {
        DetectionLocation testDetectionLocation =
                new DetectionLocation("testfile", 1, 1, List.of("test"), () -> "SSL");

        JcaMessageDigestMapper jcaMessageDigestMapper = new JcaMessageDigestMapper();
        Optional<MessageDigest> messageDigestOptional =
                jcaMessageDigestMapper.parse("SHA3-224", testDetectionLocation);

        assertThat(messageDigestOptional).isPresent();
        assertThat(messageDigestOptional.get().getName()).isEqualTo("SHA-3-224");
        assertThat(messageDigestOptional.get().getDigestSize()).isPresent();
        assertThat(messageDigestOptional.get().getDigestSize().get().getValue()).isEqualTo(224);
    }

    @Test
    void complex() {
        DetectionLocation testDetectionLocation =
                new DetectionLocation("testfile", 1, 1, List.of("test"), () -> "SSL");

        JcaMessageDigestMapper jcaMessageDigestMapper = new JcaMessageDigestMapper();
        Optional<MessageDigest> messageDigestOptional =
                jcaMessageDigestMapper.parse("SHA-512/224", testDetectionLocation);
        assertThat(messageDigestOptional).isPresent();

        MessageDigest messageDigest = messageDigestOptional.get();
        assertThat(messageDigest.getName()).isEqualTo("SHA-512/224");
        assertThat(messageDigest.getDigestSize()).isPresent();
        assertThat(messageDigest.getDigestSize().get().getValue()).isEqualTo(224);
        assertThat(messageDigest.hasChildren()).isTrue();

        Map<Class<? extends INode>, INode> children = messageDigest.getChildren();
        assertThat(children).hasSize(2);
    }
}
