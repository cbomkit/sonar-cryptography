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
import com.ibm.mapper.model.Algorithm;
import com.ibm.mapper.model.AuthenticatedEncryption;
import com.ibm.mapper.model.KeyDerivationFunction;
import com.ibm.mapper.model.KeyEncapsulationMechanism;
import com.ibm.mapper.model.KeyWrap;
import com.ibm.mapper.model.PseudorandomNumberGenerator;
import com.ibm.mapper.model.Signature;
import com.ibm.mapper.model.algorithms.AES;
import com.ibm.mapper.model.algorithms.ECDH;
import com.ibm.mapper.model.algorithms.HMAC;
import com.ibm.mapper.model.algorithms.PBKDF2;
import com.ibm.mapper.model.algorithms.RSA;
import com.ibm.mapper.model.algorithms.SHA2;
import com.ibm.mapper.model.functionality.Decapsulate;
import com.ibm.mapper.model.functionality.Decrypt;
import com.ibm.mapper.model.functionality.Digest;
import com.ibm.mapper.model.functionality.Encapsulate;
import com.ibm.mapper.model.functionality.Encrypt;
import com.ibm.mapper.model.functionality.Generate;
import com.ibm.mapper.model.functionality.KeyDerivation;
import com.ibm.mapper.model.functionality.KeyGeneration;
import com.ibm.mapper.model.functionality.Sign;
import com.ibm.mapper.model.functionality.Tag;
import com.ibm.mapper.model.functionality.Verify;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.Collections;
import org.junit.jupiter.api.Test;

class CryptoBehaviorMapperTest {

    private final IBundle bundle = () -> "Test";
    private final DetectionLocation loc =
            new DetectionLocation("test.java", 1, 1, Collections.emptyList(), bundle);
    private final CryptoBehaviorMapper mapper = new CryptoBehaviorMapper();

    @Test
    void encryptOperationYieldsEncryptsDataAndConfidentiality() {
        final AES aes = new AES(loc);
        aes.put(new Encrypt(loc));
        assertThat(mapper.map(aes))
                .containsExactlyInAnyOrder(
                        CryptoBehavior.ENCRYPTS_DATA, CryptoBehavior.ENSURES_CONFIDENTIALITY);
    }

    @Test
    void signOperationYieldsSignsDataIntegrityAndNonRepudiation() {
        final RSA rsa = new RSA(Signature.class, loc);
        rsa.put(new Sign(loc));
        assertThat(mapper.map(rsa))
                .containsExactlyInAnyOrder(
                        CryptoBehavior.SIGNS_DATA,
                        CryptoBehavior.ENSURES_INTEGRITY,
                        CryptoBehavior.ENSURES_NON_REPUDIATION);
    }

    @Test
    void encapsulateOnCipherYieldsWrapsKey() {
        final AES aes = new AES(loc); // kind BlockCipher
        aes.put(new Encapsulate(loc));
        assertThat(mapper.map(aes)).containsExactly(CryptoBehavior.WRAPS_KEY);
    }

    @Test
    void encapsulateOnKemYieldsExchangesKey() {
        final Algorithm kem = new Algorithm("ML-KEM", KeyEncapsulationMechanism.class, loc);
        kem.put(new Encapsulate(loc));
        assertThat(mapper.map(kem))
                .containsExactlyInAnyOrder(
                        CryptoBehavior.EXCHANGES_KEY, CryptoBehavior.ENSURES_CONFIDENTIALITY);
    }

    @Test
    void generateOnPrngYieldsGeneratesRandomValue() {
        final Algorithm drbg = new Algorithm("TestDRBG", PseudorandomNumberGenerator.class, loc);
        drbg.put(new Generate(loc));
        assertThat(mapper.map(drbg)).containsExactly(CryptoBehavior.GENERATES_RANDOM_VALUE);
    }

    @Test
    void keyDerivationOnPasswordBasedKdfYieldsHashesPassword() {
        final PBKDF2 pbkdf2 = new PBKDF2(loc);
        pbkdf2.put(new KeyDerivation(loc));
        assertThat(mapper.map(pbkdf2)).containsExactly(CryptoBehavior.HASHES_PASSWORD);
    }

    @Test
    void bareMessageDigestFallsBackToHashesDataAndIntegrity() {
        final SHA2 sha256 = new SHA2(256, loc); // no functionality child
        assertThat(mapper.map(sha256))
                .containsExactlyInAnyOrder(
                        CryptoBehavior.HASHES_DATA, CryptoBehavior.ENSURES_INTEGRITY);
    }

    @Test
    void bareMacFallsBackToAuthenticatesAndIntegrity() {
        final HMAC hmac = new HMAC(loc);
        assertThat(mapper.map(hmac))
                .containsExactlyInAnyOrder(
                        CryptoBehavior.AUTHENTICATES, CryptoBehavior.ENSURES_INTEGRITY);
    }

    @Test
    void bareKeyAgreementFallsBackToExchangesKey() {
        final ECDH ecdh = new ECDH(loc);
        assertThat(mapper.map(ecdh)).containsExactly(CryptoBehavior.EXCHANGES_KEY);
    }

    @Test
    void bareBlockCipherFallsBackToEncryptDecryptConfidentiality() {
        final AES aes = new AES(loc);
        assertThat(mapper.map(aes))
                .containsExactlyInAnyOrder(
                        CryptoBehavior.ENCRYPTS_DATA,
                        CryptoBehavior.DECRYPTS_DATA,
                        CryptoBehavior.ENSURES_CONFIDENTIALITY);
    }

    @Test
    void decryptOperationYieldsDecryptsDataAndConfidentiality() {
        final AES aes = new AES(loc);
        aes.put(new Decrypt(loc));
        assertThat(mapper.map(aes))
                .containsExactlyInAnyOrder(
                        CryptoBehavior.DECRYPTS_DATA, CryptoBehavior.ENSURES_CONFIDENTIALITY);
    }

    @Test
    void verifyOperationYieldsVerifiesSignatureAndIntegrity() {
        final RSA rsa = new RSA(Signature.class, loc);
        rsa.put(new Verify(loc));
        assertThat(mapper.map(rsa))
                .containsExactlyInAnyOrder(
                        CryptoBehavior.VERIFIES_SIGNATURE, CryptoBehavior.ENSURES_INTEGRITY);
    }

    @Test
    void digestOperationYieldsHashesDataAndIntegrity() {
        final SHA2 sha256 = new SHA2(256, loc);
        sha256.put(new Digest(loc));
        assertThat(mapper.map(sha256))
                .containsExactlyInAnyOrder(
                        CryptoBehavior.HASHES_DATA, CryptoBehavior.ENSURES_INTEGRITY);
    }

    @Test
    void tagOperationYieldsAuthenticatesAndIntegrity() {
        final HMAC hmac = new HMAC(loc);
        hmac.put(new Tag(loc));
        assertThat(mapper.map(hmac))
                .containsExactlyInAnyOrder(
                        CryptoBehavior.AUTHENTICATES, CryptoBehavior.ENSURES_INTEGRITY);
    }

    @Test
    void keyGenerationYieldsGeneratesKey() {
        final RSA rsa = new RSA(Signature.class, loc);
        rsa.put(new KeyGeneration(loc));
        assertThat(mapper.map(rsa)).containsExactly(CryptoBehavior.GENERATES_KEY);
    }

    @Test
    void keyDerivationOnGenericKdfYieldsGeneratesKey() {
        final Algorithm hkdf = new Algorithm("HKDF", KeyDerivationFunction.class, loc);
        hkdf.put(new KeyDerivation(loc));
        assertThat(mapper.map(hkdf)).containsExactly(CryptoBehavior.GENERATES_KEY);
    }

    @Test
    void bareAuthenticatedEncryptionFallsBackToAllFour() {
        final Algorithm aesgcm = new Algorithm("AES-GCM", AuthenticatedEncryption.class, loc);
        assertThat(mapper.map(aesgcm))
                .containsExactlyInAnyOrder(
                        CryptoBehavior.ENCRYPTS_DATA,
                        CryptoBehavior.DECRYPTS_DATA,
                        CryptoBehavior.ENSURES_CONFIDENTIALITY,
                        CryptoBehavior.ENSURES_INTEGRITY);
    }

    @Test
    void barePublicKeyEncryptionFallsBackToEncryptDecryptConfidentiality() {
        final RSA rsa = new RSA(loc); // default kind = PublicKeyEncryption
        assertThat(mapper.map(rsa))
                .containsExactlyInAnyOrder(
                        CryptoBehavior.ENCRYPTS_DATA,
                        CryptoBehavior.DECRYPTS_DATA,
                        CryptoBehavior.ENSURES_CONFIDENTIALITY);
    }

    @Test
    void bareKemFallsBackToExchangesKeyAndConfidentiality() {
        final Algorithm kem = new Algorithm("ML-KEM", KeyEncapsulationMechanism.class, loc);
        assertThat(mapper.map(kem))
                .containsExactlyInAnyOrder(
                        CryptoBehavior.EXCHANGES_KEY, CryptoBehavior.ENSURES_CONFIDENTIALITY);
    }

    @Test
    void barePrngFallsBackToGeneratesRandomValue() {
        final Algorithm drbg = new Algorithm("TestDRBG", PseudorandomNumberGenerator.class, loc);
        assertThat(mapper.map(drbg)).containsExactly(CryptoBehavior.GENERATES_RANDOM_VALUE);
    }

    @Test
    void nonAlgorithmInputYieldsEmptySet() {
        assertThat(mapper.map(new Encrypt(loc))).isEmpty();
    }

    @Test
    void encapsulateOnKeyWrapCipherYieldsWrapsKey() {
        final Algorithm aesWrap = new Algorithm("AESWrap", KeyWrap.class, loc);
        aesWrap.put(new Encapsulate(loc));
        assertThat(mapper.map(aesWrap)).containsExactly(CryptoBehavior.WRAPS_KEY);
    }

    @Test
    void decapsulateOnKeyWrapCipherYieldsWrapsKey() {
        final Algorithm aesWrap = new Algorithm("AESWrap", KeyWrap.class, loc);
        aesWrap.put(new Decapsulate(loc));
        assertThat(mapper.map(aesWrap)).containsExactly(CryptoBehavior.WRAPS_KEY);
    }

    @Test
    void bareKeyWrapCipherFallsBackToWrapsKey() {
        final Algorithm aesWrap = new Algorithm("AESWrap", KeyWrap.class, loc);
        assertThat(mapper.map(aesWrap)).containsExactly(CryptoBehavior.WRAPS_KEY);
    }
}
