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

import com.ibm.mapper.model.BlockCipher;
import com.ibm.mapper.model.Cipher;
import com.ibm.mapper.model.IAlgorithm;
import com.ibm.mapper.model.IPrimitive;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.Mode;
import com.ibm.mapper.model.PasswordBasedEncryption;
import com.ibm.mapper.model.algorithms.AES;
import com.ibm.mapper.model.algorithms.DES;
import com.ibm.mapper.model.algorithms.MD5;
import com.ibm.mapper.model.algorithms.RSA;
import com.ibm.mapper.model.mode.CFB;
import com.ibm.mapper.model.mode.ECB;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;

class JcaCipherMapperTest {

    @Test
    void base() {
        DetectionLocation testDetectionLocation =
                new DetectionLocation("testfile", 1, 1, List.of("test"), () -> "SSL");

        JcaCipherMapper jcaCipherMapper = new JcaCipherMapper();
        Optional<? extends IAlgorithm> cipherOptional =
                jcaCipherMapper.parse("AES/ECB/PKCS5Padding", testDetectionLocation);

        assertThat(cipherOptional).isPresent();
        assertThat(cipherOptional.get().is(BlockCipher.class)).isTrue();
        Cipher cipher = (Cipher) cipherOptional.get();

        assertThat(cipher.getName()).isEqualTo("AES");

        assertThat(cipher.getMode()).isPresent();
        Mode mode = cipher.getMode().get();
        assertThat(mode).isInstanceOf(ECB.class);
        assertThat(mode.getBlockSize()).isEmpty();

        assertThat(cipher.getPadding()).isPresent();
        assertThat(cipher.getPadding().get().getName()).isEqualTo("PKCS5");
    }

    @Test
    void pbe() {
        DetectionLocation testDetectionLocation =
                new DetectionLocation("testfile", 1, 1, List.of("test"), () -> "SSL");

        JcaCipherMapper jcaCipherMapper = new JcaCipherMapper();
        Optional<? extends IAlgorithm> cipherOptional =
                jcaCipherMapper.parse("PBEWithMD5AndDES", testDetectionLocation);

        assertThat(cipherOptional).isPresent();
        assertThat(cipherOptional.get().is(PasswordBasedEncryption.class)).isTrue();
        PasswordBasedEncryption pbe = (PasswordBasedEncryption) cipherOptional.get();

        assertThat(pbe.getName()).isEqualTo("PBES1");
        assertThat(pbe.asString()).isEqualTo("PBES1-DES-56-MD5");
        assertThat(pbe.hasChildren()).isTrue();
        assertThat(pbe.getChildren().values()).hasSize(2);

        assertThat(pbe.getDigest()).isPresent();

        MessageDigest digest = pbe.getDigest().get();
        assertThat(digest).isInstanceOf(MD5.class);
        assertThat(digest.getDigestSize()).isPresent();
        assertThat(digest.getDigestSize().get().getValue()).isEqualTo(128);
        assertThat(digest.getBlockSize()).isPresent();
        assertThat(digest.getBlockSize().get().getValue()).isEqualTo(512);

        assertThat(pbe.getCipher()).isPresent();
        IPrimitive encryptionAlgorithm = pbe.getCipher().get();
        assertThat(encryptionAlgorithm).isInstanceOf(DES.class);
    }

    @Test
    void blockSize() {
        DetectionLocation testDetectionLocation =
                new DetectionLocation("testfile", 1, 1, List.of("test"), () -> "SSL");

        JcaCipherMapper jcaCipherMapper = new JcaCipherMapper();
        Optional<? extends IAlgorithm> cipherOptional =
                jcaCipherMapper.parse("AES/CFB8/NoPadding", testDetectionLocation);

        assertThat(cipherOptional).isPresent();
        assertThat(cipherOptional.get().is(BlockCipher.class)).isTrue();
        Cipher cipher = (Cipher) cipherOptional.get();

        assertThat(cipher).isInstanceOf(AES.class);

        assertThat(cipher.getMode()).isPresent();
        Mode mode = cipher.getMode().get();
        assertThat(mode).isInstanceOf(CFB.class);
        assertThat(mode.getBlockSize()).isPresent();
        assertThat(mode.getBlockSize().get().getValue()).isEqualTo(8);

        assertThat(cipher.getPadding()).isEmpty();
    }

    @Test
    void rsa() {
        DetectionLocation testDetectionLocation =
                new DetectionLocation("testfile", 1, 1, List.of("test"), () -> "SSL");

        JcaCipherMapper jcaAlgorithmMapper = new JcaCipherMapper();
        Optional<? extends IAlgorithm> algorithm =
                jcaAlgorithmMapper.parse("RSA", testDetectionLocation);

        assertThat(algorithm).isPresent();
        assertThat(algorithm.get()).isInstanceOf(RSA.class);
    }
}
