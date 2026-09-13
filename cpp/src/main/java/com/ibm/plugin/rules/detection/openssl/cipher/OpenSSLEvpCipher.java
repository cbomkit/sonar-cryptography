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
package com.ibm.plugin.rules.detection.openssl.cipher;

import com.ibm.engine.model.context.CipherContext;
import com.ibm.engine.model.context.DigestContext;
import com.ibm.engine.model.factory.AlgorithmFactory;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.plugin.rules.detection.Memoize;
import com.ibm.plugin.rules.detection.openssl.digest.OpenSSLEvpMessageDigest;
import com.ibm.plugin.rules.detection.openssl.digest.OpenSSLNameCanonicalizerFactory;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.List;
import java.util.function.Supplier;
import java.util.stream.Stream;
import javax.annotation.Nonnull;

/**
 * Detection rules for OpenSSL EVP cipher algorithm specifiers.
 *
 * <p>These rules detect calls to OpenSSL functions that return EVP_CIPHER pointers, identifying the
 * specific cipher algorithm, key size, and mode of operation. Each function (e.g., {@code
 * EVP_aes_256_gcm()}) maps to a known cipher specification.
 *
 * <p>Per-family cipher specifiers live in their own {@code OpenSSLEvpCipher<Family>} classes (AES,
 * Camellia, ARIA, SM4, DES/3DES, Blowfish, CAST5, RC2, RC4, RC5, IDEA, SEED, ChaCha20); this class
 * holds the generic EVP cipher infrastructure (init, fetch, PKEY encrypt/decrypt, RSA OAEP setters,
 * CMS, PKCS#7) and aggregates every family's rules in {@link #rules()}.
 */
@SuppressWarnings("java:S1192")
public final class OpenSSLEvpCipher {

    private static final String BUNDLE = "OpenSSL";

    private static final IDetectionRule<AstNode> EVP_ENC_NULL =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_enc_null")
                    .shouldBeDetectedAs(new ValueActionFactory<>("NULL"))
                    .withoutParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_GET_CIPHERBYNAME =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_get_cipherbyname")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_ENCRYPT_INIT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_EncryptInit", "EVP_EncryptInit_ex", "EVP_EncryptInit_ex2")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ENCRYPT"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_DECRYPT_INIT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_DecryptInit", "EVP_DecryptInit_ex", "EVP_DecryptInit_ex2")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DECRYPT"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_CIPHER_INIT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_CipherInit", "EVP_CipherInit_ex", "EVP_CipherInit_ex2")
                    .shouldBeDetectedAs(new ValueActionFactory<>("CIPHER-INIT"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_ASYM_CIPHER_FETCH =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_ASYM_CIPHER_fetch")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .withMethodParameter("*")
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_PKEY_ENCRYPT_INIT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods(
                            "EVP_PKEY_encrypt_init", "EVP_PKEY_encrypt_init_ex", "EVP_PKEY_encrypt")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ENCRYPT"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_PKEY_DECRYPT_INIT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods(
                            "EVP_PKEY_decrypt_init", "EVP_PKEY_decrypt_init_ex", "EVP_PKEY_decrypt")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DECRYPT"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_PKEY_CTX_SET_RSA_PADDING =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_CTX_set_rsa_padding")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RSA-PADDING"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_PKEY_CTX_SET_RSA_OAEP_MD =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_CTX_set_rsa_oaep_md")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .addDependingDetectionRules(OpenSSLEvpMessageDigest.rules())
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_PKEY_CTX_SET_RSA_OAEP_MD_NAME =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_CTX_set_rsa_oaep_md_name")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(
                            new OpenSSLNameCanonicalizerFactory(
                                    OpenSSLNameCanonicalizerFactory.DIGEST_NAMES))
                    .withMethodParameter("*")
                    .buildForContext(new DigestContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_PKEY_CTX_SET0_RSA_OAEP_LABEL =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_CTX_set0_rsa_oaep_label")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RSA-OAEP-LABEL"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> CMS_ENCRYPT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("CMS_encrypt", "CMS_encrypt_ex")
                    .shouldBeDetectedAs(new ValueActionFactory<>("CMS-ENCRYPT"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> CMS_ENVELOPED_DATA_CREATE =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("CMS_EnvelopedData_create", "CMS_EnvelopedData_create_ex")
                    .shouldBeDetectedAs(new ValueActionFactory<>("CMS-ENVELOPED-DATA"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> CMS_AUTH_ENVELOPED_DATA_CREATE =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("CMS_AuthEnvelopedData_create", "CMS_AuthEnvelopedData_create_ex")
                    .shouldBeDetectedAs(new ValueActionFactory<>("CMS-AUTH-ENVELOPED-DATA"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> CMS_ENCRYPTED_DATA_ENCRYPT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("CMS_EncryptedData_encrypt", "CMS_EncryptedData_encrypt_ex")
                    .shouldBeDetectedAs(new ValueActionFactory<>("CMS-ENCRYPTED-DATA"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> CMS_ENCRYPTED_DATA_SET1_KEY =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("CMS_EncryptedData_set1_key")
                    .shouldBeDetectedAs(new ValueActionFactory<>("CMS-ENCRYPTED-DATA-KEY"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> CMS_ADD0_RECIPIENT_KEY =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("CMS_add0_recipient_key")
                    .shouldBeDetectedAs(new ValueActionFactory<>("CMS-RECIPIENT-KEY"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> PKCS7_ENCRYPT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("PKCS7_encrypt", "PKCS7_encrypt_ex")
                    .shouldBeDetectedAs(new ValueActionFactory<>("PKCS7-ENCRYPT"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> PKCS7_SET_CIPHER =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("PKCS7_set_cipher")
                    .shouldBeDetectedAs(new ValueActionFactory<>("PKCS7-CIPHER"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private OpenSSLEvpCipher() {
        // private
    }

    @Nonnull
    private static List<IDetectionRule<AstNode>> buildRules() {
        return Stream.of(
                        OpenSSLEvpCipherAes.rules().stream(),
                        OpenSSLEvpCipherCamellia.rules().stream(),
                        OpenSSLEvpCipherAria.rules().stream(),
                        OpenSSLEvpCipherSm4.rules().stream(),
                        OpenSSLEvpCipherDes.rules().stream(),
                        OpenSSLEvpCipherBlowfish.rules().stream(),
                        OpenSSLEvpCipherCast5.rules().stream(),
                        OpenSSLEvpCipherRc2.rules().stream(),
                        OpenSSLEvpCipherRc4.rules().stream(),
                        OpenSSLEvpCipherRc5.rules().stream(),
                        OpenSSLEvpCipherIdea.rules().stream(),
                        OpenSSLEvpCipherSeed.rules().stream(),
                        OpenSSLEvpCipherChacha20.rules().stream(),
                        directRules().stream())
                .flatMap(i -> i)
                .toList();
    }

    @Nonnull
    private static List<IDetectionRule<AstNode>> directRules() {
        return List.of(
                // NULL Cipher
                EVP_ENC_NULL,
                // Legacy lookup
                EVP_GET_CIPHERBYNAME,
                // EVP cipher init
                EVP_ENCRYPT_INIT,
                EVP_DECRYPT_INIT,
                EVP_CIPHER_INIT,
                // EVP_ASYM_CIPHER_fetch - Asymmetric cipher algorithm fetch
                EVP_ASYM_CIPHER_FETCH,
                // EVP_PKEY encrypt / decrypt
                EVP_PKEY_ENCRYPT_INIT,
                EVP_PKEY_DECRYPT_INIT,
                // RSA OAEP context setters
                EVP_PKEY_CTX_SET_RSA_PADDING,
                EVP_PKEY_CTX_SET_RSA_OAEP_MD,
                EVP_PKEY_CTX_SET_RSA_OAEP_MD_NAME,
                EVP_PKEY_CTX_SET0_RSA_OAEP_LABEL,
                // CMS - Cryptographic Message Syntax (enveloped / encrypted data)
                CMS_ENCRYPT,
                CMS_ENVELOPED_DATA_CREATE,
                CMS_AUTH_ENVELOPED_DATA_CREATE,
                CMS_ENCRYPTED_DATA_ENCRYPT,
                CMS_ENCRYPTED_DATA_SET1_KEY,
                CMS_ADD0_RECIPIENT_KEY,
                // PKCS#7 encryption functions
                PKCS7_ENCRYPT,
                PKCS7_SET_CIPHER);
    }

    private static final Supplier<List<IDetectionRule<AstNode>>> RULES =
            Memoize.of(OpenSSLEvpCipher::buildRules);

    @Nonnull
    public static List<IDetectionRule<AstNode>> rules() {
        return RULES.get();
    }
}
