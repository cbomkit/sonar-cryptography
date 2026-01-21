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
package com.ibm.plugin.rules.detection.gocrypto;

import com.ibm.engine.model.Size;
import com.ibm.engine.model.context.KeyContext;
import com.ibm.engine.model.context.SignatureContext;
import com.ibm.engine.model.factory.KeySizeFactory;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import java.util.List;
import java.util.Map;
import javax.annotation.Nonnull;
import org.sonar.plugins.go.api.Tree;

/**
 * Detection rules for Go's crypto/rsa package.
 *
 * <p>Detects usage of:
 *
 * <ul>
 *   <li>rsa.GenerateKey(random io.Reader, bits int) - generates an RSA keypair
 *   <li>rsa.EncryptPKCS1v15(random io.Reader, pub *PublicKey, msg []byte) - PKCS#1 v1.5 encryption
 *   <li>rsa.DecryptPKCS1v15(random io.Reader, priv *PrivateKey, ciphertext []byte) - PKCS#1 v1.5
 *       decryption
 *   <li>rsa.SignPKCS1v15(random io.Reader, priv *PrivateKey, hash crypto.Hash, hashed []byte) -
 *       PKCS#1 v1.5 signature
 *   <li>rsa.VerifyPKCS1v15(pub *PublicKey, hash crypto.Hash, hashed []byte, sig []byte) - PKCS#1
 *       v1.5 verification
 * </ul>
 */
@SuppressWarnings("java:S1192")
public final class GoCryptoRSA {

    private GoCryptoRSA() {
        // private
    }

    // rsa.GenerateKey(random io.Reader, bits int) (*PrivateKey, error)
    // Generates an RSA keypair of the given bit size
    private static final IDetectionRule<Tree> GENERATE_KEY =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("crypto/rsa")
                    .forMethods("GenerateKey")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RSA"))
                    .withMethodParameter("io.Reader")
                    .withMethodParameter("int")
                    .shouldBeDetectedAs(new KeySizeFactory<>(Size.UnitType.BIT))
                    .asChildOfParameterWithId(-1)
                    .buildForContext(new KeyContext(Map.of("kind", "RSA")))
                    .inBundle(() -> "GoCrypto")
                    .withoutDependingDetectionRules();

    // rsa.EncryptPKCS1v15(random io.Reader, pub *PublicKey, msg []byte) ([]byte, error)
    // Encrypts the given message with PKCS#1 v1.5
    private static final IDetectionRule<Tree> ENCRYPT_PKCS1V15 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("crypto/rsa")
                    .forMethods("EncryptPKCS1v15")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RSA-PKCS1v15"))
                    .withMethodParameter("io.Reader")
                    .withMethodParameter("*rsa.PublicKey")
                    .withMethodParameter("[]byte")
                    .buildForContext(new KeyContext(Map.of("kind", "RSA")))
                    .inBundle(() -> "GoCrypto")
                    .withoutDependingDetectionRules();

    // rsa.DecryptPKCS1v15(random io.Reader, priv *PrivateKey, ciphertext []byte) ([]byte, error)
    // Decrypts a PKCS#1 v1.5 encrypted message
    private static final IDetectionRule<Tree> DECRYPT_PKCS1V15 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("crypto/rsa")
                    .forMethods("DecryptPKCS1v15")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RSA-PKCS1v15"))
                    .withMethodParameter("io.Reader")
                    .withMethodParameter("*rsa.PrivateKey")
                    .withMethodParameter("[]byte")
                    .buildForContext(new KeyContext(Map.of("kind", "RSA")))
                    .inBundle(() -> "GoCrypto")
                    .withoutDependingDetectionRules();

    // rsa.SignPKCS1v15(random io.Reader, priv *PrivateKey, hash crypto.Hash, hashed []byte)
    // ([]byte, error)
    // Signs the hashed message using PKCS#1 v1.5
    private static final IDetectionRule<Tree> SIGN_PKCS1V15 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("crypto/rsa")
                    .forMethods("SignPKCS1v15")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RSA-PKCS1v15"))
                    .withMethodParameter("io.Reader")
                    .withMethodParameter("*rsa.PrivateKey")
                    .withMethodParameter("crypto.Hash")
                    .withMethodParameter("[]byte")
                    .buildForContext(new SignatureContext(Map.of("kind", "RSA")))
                    .inBundle(() -> "GoCrypto")
                    .withoutDependingDetectionRules();

    // rsa.VerifyPKCS1v15(pub *PublicKey, hash crypto.Hash, hashed []byte, sig []byte) error
    // Verifies a PKCS#1 v1.5 signature
    private static final IDetectionRule<Tree> VERIFY_PKCS1V15 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("crypto/rsa")
                    .forMethods("VerifyPKCS1v15")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RSA-PKCS1v15"))
                    .withMethodParameter("*rsa.PublicKey")
                    .withMethodParameter("crypto.Hash")
                    .withMethodParameter("[]byte")
                    .withMethodParameter("[]byte")
                    .buildForContext(new SignatureContext(Map.of("kind", "RSA")))
                    .inBundle(() -> "GoCrypto")
                    .withoutDependingDetectionRules();

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return List.of(
                GENERATE_KEY, ENCRYPT_PKCS1V15, DECRYPT_PKCS1V15, SIGN_PKCS1V15, VERIFY_PKCS1V15);
    }
}
