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
package com.ibm.mapper.model.algorithms;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.model.Mac;
import com.ibm.mapper.model.Mode;
import com.ibm.mapper.model.Padding;
import com.ibm.mapper.model.Signature;
import com.ibm.mapper.model.algorithms.ascon.Ascon128;
import com.ibm.mapper.model.algorithms.ascon.AsconHash;
import com.ibm.mapper.model.algorithms.ascon.AsconXof;
import com.ibm.mapper.model.algorithms.blake.BLAKE2b;
import com.ibm.mapper.model.algorithms.blake.BLAKE2s;
import com.ibm.mapper.model.algorithms.cast.CAST128;
import com.ibm.mapper.model.algorithms.cast.CAST256;
import com.ibm.mapper.model.mode.CBC;
import com.ibm.mapper.model.padding.PKCS5;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.List;
import org.junit.jupiter.api.Test;

class AlgorithmNameCompositionTest {

    static final DetectionLocation TEST =
            new DetectionLocation("testfile", 1, 1, List.of("test"), () -> "TEST");

    @Test
    void aesComposesKeyLengthAndModeWithHyphens() {
        Mode cbc = new CBC(TEST);
        AES aes = new AES(256, cbc, TEST);
        assertThat(aes.asString()).isEqualTo("AES-256-CBC");
    }

    @Test
    void sha3UsesSchemaTokenWithoutHyphenAfterSha() {
        SHA3 sha3 = new SHA3(256, TEST);
        assertThat(sha3.asString()).isEqualTo("SHA3-256");
    }

    @Test
    void desComposesKeyLengthAndModeButNotPadding() {
        Mode cbc = new CBC(TEST);
        Padding pkcs5 = new PKCS5(TEST);
        DES des = new DES(56, cbc, pkcs5, TEST);
        assertThat(des.asString()).isEqualTo("DES-56-CBC");
    }

    @Test
    void blockCipherRenamesAndComposition() {
        Mode cbc = new CBC(TEST);
        assertThat(new Aria(256, cbc, TEST).asString()).isEqualTo("ARIA-256-CBC");
        assertThat(new Camellia(256, cbc, TEST).asString()).isEqualTo("CAMELLIA-256-CBC");
        assertThat(new CAST128(128, cbc, TEST).asString()).isEqualTo("CAST5-128-CBC");
        assertThat(new CAST256(256, cbc, TEST).asString()).isEqualTo("CAST6-256-CBC");
        assertThat(new Twofish(256, cbc, TEST).asString()).isEqualTo("Twofish-256-CBC");
        assertThat(new Serpent(256, cbc, TEST).asString()).isEqualTo("Serpent-256-CBC");
        assertThat(new Blowfish(128, cbc, TEST).asString()).isEqualTo("Blowfish-128-CBC");
        assertThat(new SEED(cbc, TEST).asString()).isEqualTo("SEED-128-CBC");
        assertThat(new RC2(64, cbc, TEST).asString()).isEqualTo("RC2-64-CBC");
        assertThat(new RC5(128, cbc, TEST).asString()).isEqualTo("RC5-128-CBC");
        assertThat(new RC6(128, cbc, TEST).asString()).isEqualTo("RC6-128-CBC");
        assertThat(new TripleDES(168, cbc, TEST).asString()).isEqualTo("3DES-168-CBC");
        assertThat(new SM4(cbc, TEST).asString()).isEqualTo("SM4-CBC");
        assertThat(new IDEA(cbc, TEST).asString()).isEqualTo("IDEA-CBC");
    }

    @Test
    void keyLengthOnlyCiphers() {
        assertThat(new RC4(128, TEST).asString()).isEqualTo("RC4-128");
        assertThat(new ElGamal(2048, TEST).asString()).isEqualTo("ElGamal-2048");
    }

    @Test
    void chaCha20JoinsMacPoly1305WithHyphen() {
        ChaCha20 c = new ChaCha20(TEST);
        c.put(new Poly1305(Mac.class, new Poly1305(TEST)));
        assertThat(c.asString()).isEqualTo("ChaCha20-Poly1305");
    }

    @Test
    void chaCha20Poly1305DedicatedClassName() {
        assertThat(new ChaCha20Poly1305(TEST).asString()).isEqualTo("ChaCha20-Poly1305");
    }

    @Test
    void asconStandardizedNames() {
        assertThat(new Ascon128(TEST).asString()).isEqualTo("Ascon-AEAD128");
        assertThat(new AsconHash(TEST).asString()).isEqualTo("Ascon-Hash256");
        assertThat(new AsconXof(TEST).asString()).isEqualTo("Ascon-XOF128");
    }

    @Test
    void blake2ComposesDigestSize() {
        assertThat(new BLAKE2b(256, false, TEST).asString()).isEqualTo("BLAKE2b-256");
        assertThat(new BLAKE2s(256, false, TEST).asString()).isEqualTo("BLAKE2s-256");
    }

    @Test
    void xmssmtDropsCaretSeparator() {
        assertThat(new XMSSMT(TEST).asString()).isEqualTo("XMSSMT");
    }

    @Test
    void mlDsaAndMlKemParameterSets() {
        assertThat(new MLDSA(65, TEST).asString()).isEqualTo("ML-DSA-65");
        assertThat(new MLKEM(768, TEST).asString()).isEqualTo("ML-KEM-768");
    }

    @Test
    void rsaSignaturePutsSchemeThenDigest() {
        RSA rsa = new RSA(Signature.class, TEST);
        rsa.put(new SHA2(256, TEST));
        assertThat(rsa.asString()).isEqualTo("RSA-PKCS1-1.5-SHA-256");
    }

    @Test
    void rsaEncryptionKeyLengthUnchanged() {
        assertThat(new RSA(2048, TEST).asString()).isEqualTo("RSA-2048");
    }

    @Test
    void rsaSsaPssUsesSchemaName() {
        assertThat(new RSAssaPSS(TEST).asString()).isEqualTo("RSA-PSS");
    }

    @Test
    void dsaPutsLengthThenHash() {
        DSA dsa = new DSA(TEST);
        dsa.put(new KeyLength(2048, TEST));
        dsa.put(new SHA2(256, TEST));
        assertThat(dsa.asString()).isEqualTo("DSA-2048-SHA-256");
    }

    @Test
    void mqvUsesFiniteFieldName() {
        assertThat(new MQV(TEST).asString()).isEqualTo("FFMQV");
    }

    @Test
    void cmacPutsCipherAfterName() {
        CMAC cmac = new CMAC(new AES(TEST));
        assertThat(cmac.asString()).isEqualTo("CMAC-AES");
    }

    @Test
    void kdfSchemaNames() {
        assertThat(new Scrypt(TEST).asString()).isEqualTo("scrypt");
        assertThat(new KDFDoublePipeline(TEST).asString()).isEqualTo("SP800_108_DoublePipelineKDF");
        assertThat(new ANSIX942(TEST).asString()).isEqualTo("ANSI-KDF-X9.42");
        assertThat(new ANSIX963(TEST).asString()).isEqualTo("ANSI-KDF-X9.63");
    }
}
