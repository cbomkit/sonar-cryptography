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
package com.ibm.mapper.reorganizer.rules;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

import com.ibm.mapper.model.EllipticCurve;
import com.ibm.mapper.model.EllipticCurveAlgorithm;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.Key;
import com.ibm.mapper.model.KeyAgreement;
import com.ibm.mapper.model.KeyEncapsulationMechanism;
import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.model.Mac;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.PrivateKey;
import com.ibm.mapper.model.ProbabilisticSignatureScheme;
import com.ibm.mapper.model.PublicKeyEncryption;
import com.ibm.mapper.model.SecretKey;
import com.ibm.mapper.model.Signature;
import com.ibm.mapper.model.algorithms.DH;
import com.ibm.mapper.model.algorithms.DHKEM;
import com.ibm.mapper.model.algorithms.ECDH;
import com.ibm.mapper.model.algorithms.ECDSA;
import com.ibm.mapper.model.algorithms.Ed25519;
import com.ibm.mapper.model.algorithms.HMAC;
import com.ibm.mapper.model.algorithms.RSA;
import com.ibm.mapper.model.algorithms.RSASVE;
import com.ibm.mapper.model.algorithms.RSAssaPSS;
import com.ibm.mapper.model.algorithms.SHA2;
import com.ibm.mapper.model.algorithms.X25519;
import com.ibm.mapper.model.curves.Secp256r1;
import com.ibm.mapper.model.functionality.Decapsulate;
import com.ibm.mapper.model.functionality.Decrypt;
import com.ibm.mapper.model.functionality.Encapsulate;
import com.ibm.mapper.model.functionality.KeyDerivation;
import com.ibm.mapper.model.functionality.KeyGeneration;
import com.ibm.mapper.model.functionality.Sign;
import com.ibm.mapper.model.functionality.Tag;
import com.ibm.mapper.model.functionality.Verify;
import com.ibm.mapper.reorganizer.IReorganizerRule;
import com.ibm.mapper.reorganizer.Reorganizer;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

class KeyUsageReorganizerTest {

    private final DetectionLocation location = mock(DetectionLocation.class);

    @Test
    void anOperationAlgorithmOnTheKeysAlgorithmIsHeldByTheKeyWithTheKeysCurve() {
        // EC_KEY_generate_key(key); ECDSA_do_sign(dgst, len, key)
        final EllipticCurveAlgorithm algorithm =
                new EllipticCurveAlgorithm(new Secp256r1(location));
        algorithm.put(new KeyGeneration(location));
        algorithm.put(new ECDSA(location));
        final PrivateKey key = new PrivateKey((PublicKeyEncryption) algorithm);

        final List<INode> result =
                new Reorganizer(
                                List.of(
                                        KeyUsageReorganizer
                                                .MOVE_OPERATION_ALGORITHMS_OF_PRIVATE_KEY_TO_THE_KEY))
                        .reorganize(new ArrayList<>(List.of(key)));

        assertThat(result).singleElement().isSameAs(key);
        assertThat(key.hasChildOfType(PublicKeyEncryption.class)).isEmpty();
        assertThat(key.hasChildOfType(KeyGeneration.class)).isPresent();
        assertThat(key.hasChildOfType(Signature.class))
                .get()
                .isInstanceOf(ECDSA.class)
                .satisfies(
                        signature ->
                                assertThat(
                                                signature
                                                        .hasChildOfType(EllipticCurve.class)
                                                        .map(INode::asString))
                                        .contains("secp256r1"));
    }

    @Test
    void anAlgorithmInsideAnOperationOfTheKeyStaysThere() {
        // EVP_PKEY_Q_keygen(NULL, NULL, "X25519"); EVP_PKEY_encapsulate(...): DHKEM over X25519
        final ECDSA component = new ECDSA(location);
        final DHKEM kem = new DHKEM(component, location);
        final EllipticCurveAlgorithm algorithm =
                new EllipticCurveAlgorithm(new Secp256r1(location));
        final PrivateKey key = new PrivateKey((PublicKeyEncryption) algorithm);
        key.removeChildOfType(PublicKeyEncryption.class);
        key.put(kem);

        new Reorganizer(
                        List.of(
                                KeyUsageReorganizer
                                        .MOVE_OPERATION_ALGORITHMS_OF_PRIVATE_KEY_TO_THE_KEY))
                .reorganize(new ArrayList<>(List.of(key)));

        assertThat(key.hasChildOfType(Signature.class)).isEmpty();
        assertThat(kem.hasChildOfType(Signature.class)).isPresent();
    }

    @Test
    void aDecryptionWithAnEcKeyIsAnEcdhKeyAgreement() {
        // EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256"); CMS_decrypt(cms, pkey, ...)
        final EllipticCurveAlgorithm algorithm =
                new EllipticCurveAlgorithm(new Secp256r1(location));
        algorithm.put(new KeyGeneration(location));
        algorithm.put(new Decrypt(location));
        final PrivateKey key = new PrivateKey((PublicKeyEncryption) algorithm);

        new Reorganizer(
                        List.of(
                                KeyUsageReorganizer
                                        .MAKE_KEY_DERIVATION_OF_A_DECRYPTION_WITH_A_KEY_AGREEMENT_KEY,
                                KeyUsageReorganizer.MAKE_ALGORITHMS_OF_PRIVATE_KEY_OPERATIONS))
                .reorganize(new ArrayList<>(List.of(key)));

        assertThat(key.hasChildOfType(PublicKeyEncryption.class)).isEmpty();
        assertThat(key.hasChildOfType(KeyAgreement.class))
                .get()
                .isInstanceOf(ECDH.class)
                .satisfies(
                        agreement -> {
                            assertThat(agreement.hasChildOfType(KeyDerivation.class)).isPresent();
                            assertThat(agreement.hasChildOfType(Decrypt.class)).isEmpty();
                            assertThat(
                                            agreement
                                                    .hasChildOfType(EllipticCurve.class)
                                                    .map(INode::asString))
                                    .contains("secp256r1");
                        });
    }

    @Test
    void aDecryptionWithAnX25519KeyIsItsKeyAgreement() {
        // EVP_PKEY_Q_keygen(NULL, NULL, "X25519"); CMS_decrypt(cms, pkey, ...)
        final X25519 algorithm = new X25519(location);
        algorithm.put(new KeyGeneration(location));
        algorithm.put(new Decrypt(location));
        final PrivateKey key = new PrivateKey(new Key(algorithm));

        new Reorganizer(
                        List.of(
                                KeyUsageReorganizer
                                        .MAKE_KEY_DERIVATION_OF_A_DECRYPTION_WITH_A_KEY_AGREEMENT_KEY))
                .reorganize(new ArrayList<>(List.of(key)));

        assertThat(algorithm.hasChildOfType(KeyDerivation.class)).isPresent();
        assertThat(algorithm.hasChildOfType(Decrypt.class)).isEmpty();
    }

    @Test
    void aDecryptionWithAnRsaKeyStaysADecryption() {
        // EVP_PKEY_Q_keygen(NULL, NULL, "RSA", 2048); CMS_decrypt(cms, pkey, ...)
        final RSA algorithm = new RSA(location);
        algorithm.put(new KeyGeneration(location));
        algorithm.put(new Decrypt(location));
        final PrivateKey key = new PrivateKey((PublicKeyEncryption) algorithm);

        new Reorganizer(
                        List.of(
                                KeyUsageReorganizer
                                        .MAKE_KEY_DERIVATION_OF_A_DECRYPTION_WITH_A_KEY_AGREEMENT_KEY))
                .reorganize(new ArrayList<>(List.of(key)));

        assertThat(algorithm.hasChildOfType(Decrypt.class)).isPresent();
        assertThat(algorithm.hasChildOfType(KeyDerivation.class)).isEmpty();
    }

    private void reorganize(INode key, IReorganizerRule... rules) {
        new Reorganizer(List.of(rules)).reorganize(new ArrayList<>(List.of(key)));
    }

    @Test
    void signaturesWithAnEcKeyAreEcdsaOnTheKeysCurve() {
        // EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256"); EVP_DigestSignInit(...); ...VerifyInit(...)
        final EllipticCurveAlgorithm algorithm =
                new EllipticCurveAlgorithm(new Secp256r1(location));
        algorithm.put(new KeyGeneration(location));
        algorithm.put(new Sign(location));
        algorithm.put(new Verify(location));
        final PrivateKey key = new PrivateKey((PublicKeyEncryption) algorithm);

        reorganize(key, KeyUsageReorganizer.MAKE_ALGORITHMS_OF_PRIVATE_KEY_OPERATIONS);

        assertThat(key.hasChildOfType(PublicKeyEncryption.class)).isEmpty();
        assertThat(key.hasChildOfType(KeyGeneration.class)).isPresent();
        assertThat(key.hasChildOfType(Signature.class))
                .get()
                .isInstanceOf(ECDSA.class)
                .satisfies(
                        ecdsa -> {
                            assertThat(ecdsa.hasChildOfType(Sign.class)).isPresent();
                            assertThat(ecdsa.hasChildOfType(Verify.class)).isPresent();
                            assertThat(ecdsa.hasChildOfType(EllipticCurve.class))
                                    .map(INode::asString)
                                    .contains("secp256r1");
                        });
    }

    @Test
    void aSignatureWithAnRsaKeyIsAnRsaSignatureOfTheKeysLength() {
        // RSA key of 2048 bits, signing and decrypting
        final RSA algorithm = new RSA(2048, location);
        algorithm.put(new KeyGeneration(location));
        algorithm.put(new Sign(location));
        algorithm.put(new Decrypt(location));
        final PrivateKey key = new PrivateKey((PublicKeyEncryption) algorithm);

        reorganize(key, KeyUsageReorganizer.MAKE_ALGORITHMS_OF_PRIVATE_KEY_OPERATIONS);

        assertThat(key.hasChildOfType(Signature.class))
                .get()
                .isInstanceOf(RSA.class)
                .satisfies(
                        signature -> {
                            assertThat(signature.hasChildOfType(Sign.class)).isPresent();
                            assertThat(signature.hasChildOfType(KeyLength.class))
                                    .map(INode::asString)
                                    .contains("2048");
                        });
        // the decryption is the key's own algorithm, which stays with it
        assertThat(algorithm.hasChildOfType(Decrypt.class)).isPresent();
        assertThat(key.hasChildOfType(PublicKeyEncryption.class)).get().isSameAs(algorithm);
    }

    @Test
    void aSignatureWithTheRsaPssPaddingIsRsaPss() {
        final RSA algorithm = new RSA(3072, location);
        final Sign sign = new Sign(location);
        sign.put(new RSAssaPSS(location));
        algorithm.put(sign);
        final PrivateKey key = new PrivateKey((PublicKeyEncryption) algorithm);

        reorganize(key, KeyUsageReorganizer.MAKE_ALGORITHMS_OF_PRIVATE_KEY_OPERATIONS);

        assertThat(key.hasChildOfType(ProbabilisticSignatureScheme.class))
                .get()
                .isInstanceOf(RSAssaPSS.class)
                .satisfies(
                        pss ->
                                assertThat(pss.hasChildOfType(KeyLength.class))
                                        .map(INode::asString)
                                        .contains("3072"));
    }

    @Test
    void keyAgreementWithAnEcOrDhKeyIsEcdhOrDh() {
        final EllipticCurveAlgorithm ec = new EllipticCurveAlgorithm(new Secp256r1(location));
        ec.put(new KeyDerivation(location));
        final PrivateKey ecKey = new PrivateKey((PublicKeyEncryption) ec);
        final DH dh = new DH(location);
        dh.put(new KeyLength(2048, location));
        dh.put(new KeyDerivation(location));
        final PrivateKey dhKey = new PrivateKey((PublicKeyEncryption) dh);

        reorganize(ecKey, KeyUsageReorganizer.MAKE_ALGORITHMS_OF_PRIVATE_KEY_OPERATIONS);
        reorganize(dhKey, KeyUsageReorganizer.MAKE_ALGORITHMS_OF_PRIVATE_KEY_OPERATIONS);

        assertThat(ecKey.hasChildOfType(KeyAgreement.class)).get().isInstanceOf(ECDH.class);
        assertThat(dhKey.hasChildOfType(KeyAgreement.class))
                .get()
                .isInstanceOf(DH.class)
                .satisfies(
                        agreement ->
                                assertThat(agreement.hasChildOfType(KeyLength.class))
                                        .map(INode::asString)
                                        .contains("2048"));
    }

    @Test
    void keyEncapsulationIsRsasveWithAnRsaKeyAndDhkemWithAnEcKey() {
        final RSA rsa = new RSA(2048, location);
        rsa.put(new Encapsulate(location));
        final PrivateKey rsaKey = new PrivateKey((PublicKeyEncryption) rsa);
        final EllipticCurveAlgorithm ec = new EllipticCurveAlgorithm(new Secp256r1(location));
        ec.put(new Decapsulate(location));
        final PrivateKey ecKey = new PrivateKey((PublicKeyEncryption) ec);

        reorganize(rsaKey, KeyUsageReorganizer.MAKE_ALGORITHMS_OF_PRIVATE_KEY_OPERATIONS);
        reorganize(ecKey, KeyUsageReorganizer.MAKE_ALGORITHMS_OF_PRIVATE_KEY_OPERATIONS);

        assertThat(rsaKey.hasChildOfType(KeyEncapsulationMechanism.class))
                .get()
                .isInstanceOf(RSASVE.class);
        assertThat(ecKey.hasChildOfType(KeyEncapsulationMechanism.class))
                .get()
                .isInstanceOf(DHKEM.class)
                .satisfies(
                        dhkem ->
                                assertThat(dhkem.hasChildOfType(KeyAgreement.class))
                                        .get()
                                        .isInstanceOf(ECDH.class));
    }

    @Test
    void aSignatureWithAnEd25519KeyIsTheKeysOwnAlgorithm() {
        final Ed25519 algorithm = new Ed25519(location);
        algorithm.put(new Sign(location));
        final PrivateKey key = new PrivateKey((Signature) algorithm);

        reorganize(key, KeyUsageReorganizer.MAKE_ALGORITHMS_OF_PRIVATE_KEY_OPERATIONS);

        assertThat(key.hasChildOfType(Signature.class)).get().isSameAs(algorithm);
        assertThat(algorithm.hasChildOfType(Sign.class)).isPresent();
    }

    @Test
    void theOperationsOfAnImportedKeyAreMovedUnderItsAlgorithm() {
        // EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, ...); EVP_DigestSign(...)
        final Ed25519 algorithm = new Ed25519(location);
        final PrivateKey key = new PrivateKey(new Key(algorithm));
        key.put(new Sign(location));

        reorganize(
                key,
                KeyUsageReorganizer.moveOperationsOfImportedKeyUnderItsAlgorithm(PrivateKey.class));

        assertThat(key.hasChildOfType(Sign.class)).isEmpty();
        assertThat(algorithm.hasChildOfType(Sign.class)).isPresent();
    }

    @Test
    void theOperationsOfAGeneratedKeyStayOnTheKey() {
        final Ed25519 algorithm = new Ed25519(location);
        algorithm.put(new KeyGeneration(location));
        final PrivateKey key = new PrivateKey(new Key(algorithm));
        key.put(new Sign(location));

        reorganize(
                key,
                KeyUsageReorganizer.moveOperationsOfImportedKeyUnderItsAlgorithm(PrivateKey.class));

        assertThat(key.hasChildOfType(Sign.class)).isPresent();
        assertThat(algorithm.hasChildOfType(Sign.class)).isEmpty();
    }

    @Test
    void theOperationsOfAKeyMarkedGeneratedStayOnTheKey() {
        final Ed25519 algorithm = new Ed25519(location);
        final PrivateKey key = new PrivateKey(new Key(algorithm));
        key.put(new KeyGeneration(location));
        key.put(new Sign(location));

        reorganize(
                key,
                KeyUsageReorganizer.moveOperationsOfImportedKeyUnderItsAlgorithm(PrivateKey.class));

        assertThat(key.hasChildOfType(Sign.class)).isPresent();
        assertThat(algorithm.hasChildOfType(Sign.class)).isEmpty();
    }

    @Test
    void aSignatureWithAMacKeyIsATagOfTheMac() {
        // EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, ...); EVP_DigestSignInit(mdctx, NULL, md, NULL, key)
        final HMAC hmac = new HMAC(location);
        final Sign sign = new Sign(location);
        final MessageDigest digest = new SHA2(256, location);
        sign.put(digest);
        hmac.put(sign);
        final SecretKey key = new SecretKey(new Key(hmac));

        reorganize(key, KeyUsageReorganizer.MAKE_TAGS_OF_SECRET_KEY_OPERATIONS);

        assertThat(hmac.hasChildOfType(Sign.class)).isEmpty();
        assertThat(hmac.hasChildOfType(Tag.class)).isPresent();
        assertThat(hmac.hasChildOfType(MessageDigest.class)).get().isSameAs(digest);
        assertThat(key.hasChildOfType(Mac.class)).get().isSameAs(hmac);
    }
}
