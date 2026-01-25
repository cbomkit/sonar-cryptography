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

import com.ibm.mapper.model.Cipher;
import com.ibm.mapper.model.Mac;
import com.ibm.mapper.model.PasswordBasedEncryption;
import com.ibm.mapper.model.algorithms.AES;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;

class JcaPasswordBasedEncryptionMapperTest {

    @Test
    void base() {
        DetectionLocation testDetectionLocation =
                new DetectionLocation("testfile", 1, 1, List.of("test"), () -> "SSL");

        JcaPasswordBasedEncryptionMapper jcaPasswordBasedEncryptionMapper =
                new JcaPasswordBasedEncryptionMapper();
        Optional<PasswordBasedEncryption> pbeOpt =
                jcaPasswordBasedEncryptionMapper.parse(
                        "PBEWithHmacSHA256AndAES", testDetectionLocation);

        assertThat(pbeOpt).isPresent();
        PasswordBasedEncryption pbe = pbeOpt.get();
        assertThat(pbe.getName()).isEqualTo("PBES1");
        assertThat(pbe.asString()).isEqualTo("pbeWithHmacSHA-256AndAES");

        assertThat(pbe.getChildren()).hasSize(2);
        assertThat(pbe.getDigest()).isEmpty();
        assertThat(pbe.getCipher()).isPresent();
        assertThat(pbe.getMac()).isPresent();

        Mac mac = pbe.getMac().get();
        assertThat(mac.asString()).isEqualTo("HMAC-SHA-256");
        assertThat(mac.getChildren()).hasSize(1);

        Cipher cipher = pbe.getCipher().get();
        assertThat(cipher).isInstanceOf(AES.class);
    }
}
