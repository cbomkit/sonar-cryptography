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
import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.model.Mode;
import com.ibm.mapper.model.Padding;
import com.ibm.mapper.model.algorithms.AES;
import com.ibm.mapper.model.algorithms.ChaCha20Poly1305;
import com.ibm.mapper.model.algorithms.DESX;
import com.ibm.mapper.model.algorithms.RSA;
import com.ibm.mapper.model.mode.CBC;
import com.ibm.mapper.model.mode.CFB;
import com.ibm.mapper.model.mode.ECB;
import com.ibm.mapper.model.mode.OFB;
import com.ibm.mapper.model.padding.OAEP;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.List;
import org.junit.jupiter.api.Test;

class OpenSslCipherMapperTest {

    private final DetectionLocation location =
            new DetectionLocation("testfile", 1, 1, List.of("test"), () -> "OpenSSL");
    private final OpenSslCipherMapper mapper = new OpenSslCipherMapper();

    private INode parse(String name) {
        return mapper.parse(name, location).orElseThrow();
    }

    @Test
    void aesWithKeyLengthAndMode() {
        INode aes = parse("aes-256-gcm");
        assertThat(aes).isInstanceOf(AES.class);
        assertThat(aes.getChildren().get(KeyLength.class).asString()).isEqualTo("256");
        assertThat(aes.getChildren().get(Mode.class).asString()).isEqualTo("GCM");
    }

    @Test
    void cfbWithItsFeedbackSize() {
        INode aes = parse("AES-128-CFB8");
        assertThat(aes.getChildren().get(Mode.class)).isInstanceOf(CFB.class);
        assertThat(aes.getChildren().get(Mode.class).asString()).isEqualTo("CFB8");
    }

    @Test
    void legacyAesFunctionsWithTheirModeClass() {
        assertThat(parse("AES-CBC").getChildren().get(Mode.class)).isInstanceOf(CBC.class);
        assertThat(parse("AES-ECB").getChildren().get(Mode.class)).isInstanceOf(ECB.class);
        assertThat(parse("AES-OFB").getChildren().get(Mode.class)).isInstanceOf(OFB.class);
        assertThat(parse("AES-CFB128").getChildren().get(Mode.class)).isInstanceOf(CFB.class);
        assertThat(parse("AES-IGE").getChildren().get(Mode.class).asString()).isEqualTo("IGE");
    }

    @Test
    void legacyFunctionsTakeTheKeyLengthOfTheirKey() {
        // EVP_bf_cbc: 128 bits unless set otherwise
        assertThat(parse("BLOWFISH-CBC").getChildren().get(KeyLength.class).asString())
                .isEqualTo("128");
        // BF_cbc_encrypt: the key length of the key set up by BF_set_key
        for (String legacy : List.of("BLOWFISH-CBC", "CAST5-ECB", "RC2-OFB", "RC5-CFB")) {
            final INode cipher = mapper.parseLegacy(legacy, location).orElseThrow();
            assertThat(cipher.hasChildOfType(KeyLength.class)).as(legacy).isEmpty();
            assertThat(cipher.hasChildOfType(Mode.class)).as(legacy).isPresent();
        }
        // a cipher whose key length is fixed keeps it
        assertThat(
                        mapper.parseLegacy("DES-CBC", location)
                                .orElseThrow()
                                .getChildren()
                                .get(KeyLength.class)
                                .asString())
                .isEqualTo("56");
    }

    @Test
    void desx() {
        INode desx = parse("DESX-CBC");
        assertThat(desx).isInstanceOf(DESX.class);
        assertThat(desx.asString()).isEqualTo("DESX-184-CBC");
    }

    @Test
    void aeadAndPublicKeyCiphers() {
        assertThat(parse("ChaCha20-Poly1305")).isInstanceOf(ChaCha20Poly1305.class);
        INode rsaOaep = parse("RSA-OAEP");
        assertThat(rsaOaep).isInstanceOf(RSA.class);
        assertThat(rsaOaep.getChildren().get(Padding.class)).isInstanceOf(OAEP.class);
    }

    @Test
    void unknownAndNullNames() {
        assertThat(mapper.parse("XYZ", location)).isEmpty();
        assertThat(mapper.parse(null, location)).isEmpty();
    }
}
