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

import com.ibm.engine.model.CipherAction;
import com.ibm.engine.model.context.CipherContext;
import com.ibm.engine.model.context.DigestContext;
import com.ibm.engine.model.factory.AlgorithmFactory;
import com.ibm.engine.model.factory.CipherActionFactory;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.plugin.rules.detection.Memoize;
import com.ibm.plugin.rules.detection.openssl.digest.OpenSSLNameCanonicalizerFactory;
import com.ibm.plugin.rules.detection.openssl.legacy.OpenSSLNidLookupFactory;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.List;
import java.util.Map;
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
 * holds the generic EVP cipher infrastructure (init, fetch, RSA padding and OAEP setters, and the
 * CMS and PKCS#7 functions that take a content encryption cipher or a key wrap algorithm) and
 * aggregates every family's rules in {@link #rules()}.
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
                    .shouldBeDetectedAs(
                            new OpenSSLNameCanonicalizerFactory(
                                    OpenSSLNameCanonicalizerFactory.CIPHER_NAMES))
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    /**
     * The calls that select a cipher: the EVP_* cipher functions, EVP_CIPHER_fetch and
     * EVP_get_cipherbyname. The cipher argument of the init functions below is traced back to one
     * of them.
     */
    private static final List<IDetectionRule<AstNode>> CIPHER_SELECTION =
            Stream.of(
                            cipherFamilyRules().stream(),
                            OpenSSLEvpCipherFetch.rules().stream(),
                            Stream.of(EVP_ENC_NULL, EVP_GET_CIPHERBYNAME))
                    .flatMap(i -> i)
                    .toList();

    // Cipher initialization: (ctx, cipher, ...) for encryption or decryption

    private static final IDetectionRule<AstNode> EVP_ENCRYPT_INIT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_EncryptInit")
                    .shouldBeDetectedAs(new CipherActionFactory<>(CipherAction.Action.ENCRYPT))
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .addDependingDetectionRules(CIPHER_SELECTION)
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_ENCRYPT_INIT_EX =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_EncryptInit_ex", "EVP_EncryptInit_ex2")
                    .shouldBeDetectedAs(new CipherActionFactory<>(CipherAction.Action.ENCRYPT))
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .addDependingDetectionRules(CIPHER_SELECTION)
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_DECRYPT_INIT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_DecryptInit")
                    .shouldBeDetectedAs(new CipherActionFactory<>(CipherAction.Action.DECRYPT))
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .addDependingDetectionRules(CIPHER_SELECTION)
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_DECRYPT_INIT_EX =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_DecryptInit_ex", "EVP_DecryptInit_ex2")
                    .shouldBeDetectedAs(new CipherActionFactory<>(CipherAction.Action.DECRYPT))
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .addDependingDetectionRules(CIPHER_SELECTION)
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // EVP_CipherInit: the operation is given by the enc argument (1 encrypts, 0 decrypts)

    private static final IDetectionRule<AstNode> EVP_CIPHER_INIT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_CipherInit")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .addDependingDetectionRules(CIPHER_SELECTION)
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(new OpenSSLCipherOperationFactory())
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_CIPHER_INIT_EX =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_CipherInit_ex")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .addDependingDetectionRules(CIPHER_SELECTION)
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(new OpenSSLCipherOperationFactory())
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_CIPHER_INIT_EX2 =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_CipherInit_ex2")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .addDependingDetectionRules(CIPHER_SELECTION)
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(new OpenSSLCipherOperationFactory())
                    .withMethodParameter("*")
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

    /** RSA padding mode (rsa.h) → the RSA scheme it selects. */
    private static final Map<Integer, String> RSA_PADDING_BY_CODE =
            Map.ofEntries(
                    Map.entry(1, "RSA-PKCS1-TYPE2"), // RSA_PKCS1_PADDING
                    Map.entry(3, "RSA-NO-PADDING"), // RSA_NO_PADDING
                    Map.entry(4, "RSA-OAEP"), // RSA_PKCS1_OAEP_PADDING
                    Map.entry(5, "RSA-X931"), // RSA_X931_PADDING
                    Map.entry(6, "RSA-PSS"), // RSA_PKCS1_PSS_PADDING
                    Map.entry(7, "RSA-PKCS1-TYPE2"), // RSA_PKCS1_WITH_TLS_PADDING
                    Map.entry(8, "RSA-PKCS1-TYPE2")); // RSA_PKCS1_NO_IMPLICIT_REJECT_PADDING

    private static final Map<String, String> RSA_PADDING_BY_NAME =
            Map.ofEntries(
                    Map.entry("RSA_PKCS1_PADDING", "RSA-PKCS1-TYPE2"),
                    Map.entry("RSA_NO_PADDING", "RSA-NO-PADDING"),
                    Map.entry("RSA_PKCS1_OAEP_PADDING", "RSA-OAEP"),
                    Map.entry("RSA_X931_PADDING", "RSA-X931"),
                    Map.entry("RSA_PKCS1_PSS_PADDING", "RSA-PSS"),
                    Map.entry("RSA_PKCS1_WITH_TLS_PADDING", "RSA-PKCS1-TYPE2"),
                    Map.entry("RSA_PKCS1_NO_IMPLICIT_REJECT_PADDING", "RSA-PKCS1-TYPE2"));

    private static final IDetectionRule<AstNode> EVP_PKEY_CTX_SET_RSA_PADDING =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_CTX_set_rsa_padding")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(
                            new OpenSSLNidLookupFactory(RSA_PADDING_BY_CODE, RSA_PADDING_BY_NAME))
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

    // CMS and PKCS#7 encryption: the content encryption cipher is an argument, e.g.
    // CMS_encrypt(certs, in, cipher, flags)

    private static final IDetectionRule<AstNode> CMS_ENCRYPT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("CMS_encrypt")
                    .shouldBeDetectedAs(new CipherActionFactory<>(CipherAction.Action.ENCRYPT))
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .addDependingDetectionRules(CIPHER_SELECTION)
                    .withMethodParameter("*")
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> CMS_ENCRYPT_EX =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("CMS_encrypt_ex")
                    .shouldBeDetectedAs(new CipherActionFactory<>(CipherAction.Action.ENCRYPT))
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .addDependingDetectionRules(CIPHER_SELECTION)
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> CMS_ENVELOPED_DATA_CREATE =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("CMS_EnvelopedData_create")
                    .shouldBeDetectedAs(new CipherActionFactory<>(CipherAction.Action.ENCRYPT))
                    .withMethodParameter("*")
                    .addDependingDetectionRules(CIPHER_SELECTION)
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> CMS_ENVELOPED_DATA_CREATE_EX =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("CMS_EnvelopedData_create_ex")
                    .shouldBeDetectedAs(new CipherActionFactory<>(CipherAction.Action.ENCRYPT))
                    .withMethodParameter("*")
                    .addDependingDetectionRules(CIPHER_SELECTION)
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> CMS_AUTH_ENVELOPED_DATA_CREATE =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("CMS_AuthEnvelopedData_create")
                    .shouldBeDetectedAs(new CipherActionFactory<>(CipherAction.Action.ENCRYPT))
                    .withMethodParameter("*")
                    .addDependingDetectionRules(CIPHER_SELECTION)
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> CMS_AUTH_ENVELOPED_DATA_CREATE_EX =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("CMS_AuthEnvelopedData_create_ex")
                    .shouldBeDetectedAs(new CipherActionFactory<>(CipherAction.Action.ENCRYPT))
                    .withMethodParameter("*")
                    .addDependingDetectionRules(CIPHER_SELECTION)
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> CMS_ENCRYPTED_DATA_ENCRYPT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("CMS_EncryptedData_encrypt")
                    .shouldBeDetectedAs(new CipherActionFactory<>(CipherAction.Action.ENCRYPT))
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .addDependingDetectionRules(CIPHER_SELECTION)
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> CMS_ENCRYPTED_DATA_ENCRYPT_EX =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("CMS_EncryptedData_encrypt_ex")
                    .shouldBeDetectedAs(new CipherActionFactory<>(CipherAction.Action.ENCRYPT))
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .addDependingDetectionRules(CIPHER_SELECTION)
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> CMS_ENCRYPTED_DATA_SET1_KEY =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("CMS_EncryptedData_set1_key")
                    .shouldBeDetectedAs(new CipherActionFactory<>(CipherAction.Action.ENCRYPT))
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .addDependingDetectionRules(CIPHER_SELECTION)
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> PKCS7_ENCRYPT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("PKCS7_encrypt")
                    .shouldBeDetectedAs(new CipherActionFactory<>(CipherAction.Action.ENCRYPT))
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .addDependingDetectionRules(CIPHER_SELECTION)
                    .withMethodParameter("*")
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> PKCS7_ENCRYPT_EX =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("PKCS7_encrypt_ex")
                    .shouldBeDetectedAs(new CipherActionFactory<>(CipherAction.Action.ENCRYPT))
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .addDependingDetectionRules(CIPHER_SELECTION)
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> PKCS7_SET_CIPHER =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("PKCS7_set_cipher")
                    .shouldBeDetectedAs(new CipherActionFactory<>(CipherAction.Action.ENCRYPT))
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .addDependingDetectionRules(CIPHER_SELECTION)
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // CMS_add0_recipient_key(cms, nid, key, keylen, id, idlen, date, otherTypeId, otherType): the
    // key wrap algorithm of a KEK recipient

    private static final IDetectionRule<AstNode> CMS_ADD0_RECIPIENT_KEY =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("CMS_add0_recipient_key")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(
                            new OpenSSLNidLookupFactory(
                                    OpenSSLNidLookupFactory.KEY_WRAP_BY_CODE,
                                    OpenSSLNidLookupFactory.KEY_WRAP_BY_NAME))
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private OpenSSLEvpCipher() {
        // private
    }

    @Nonnull
    private static List<IDetectionRule<AstNode>> buildRules() {
        return Stream.of(cipherFamilyRules().stream(), directRules().stream())
                .flatMap(i -> i)
                .toList();
    }

    @Nonnull
    private static List<IDetectionRule<AstNode>> cipherFamilyRules() {
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
                        OpenSSLEvpCipherChacha20.rules().stream())
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
                EVP_ENCRYPT_INIT_EX,
                EVP_DECRYPT_INIT,
                EVP_DECRYPT_INIT_EX,
                EVP_CIPHER_INIT,
                EVP_CIPHER_INIT_EX,
                EVP_CIPHER_INIT_EX2,
                // EVP_ASYM_CIPHER_fetch - Asymmetric cipher algorithm fetch
                EVP_ASYM_CIPHER_FETCH,
                // RSA OAEP context setters
                EVP_PKEY_CTX_SET_RSA_PADDING,
                EVP_PKEY_CTX_SET_RSA_OAEP_MD_NAME,
                // CMS - Cryptographic Message Syntax (enveloped / encrypted data)
                CMS_ENCRYPT,
                CMS_ENCRYPT_EX,
                CMS_ENVELOPED_DATA_CREATE,
                CMS_ENVELOPED_DATA_CREATE_EX,
                CMS_AUTH_ENVELOPED_DATA_CREATE,
                CMS_AUTH_ENVELOPED_DATA_CREATE_EX,
                CMS_ENCRYPTED_DATA_ENCRYPT,
                CMS_ENCRYPTED_DATA_ENCRYPT_EX,
                CMS_ENCRYPTED_DATA_SET1_KEY,
                CMS_ADD0_RECIPIENT_KEY,
                // PKCS#7 encryption functions
                PKCS7_ENCRYPT,
                PKCS7_ENCRYPT_EX,
                PKCS7_SET_CIPHER);
    }

    private static final Supplier<List<IDetectionRule<AstNode>>> RULES =
            Memoize.of(OpenSSLEvpCipher::buildRules);

    @Nonnull
    public static List<IDetectionRule<AstNode>> rules() {
        return RULES.get();
    }

    /**
     * The rule for the RSA padding set on a context ({@code EVP_PKEY_CTX_set_rsa_padding}), for the
     * operations performed with an RSA key.
     */
    @Nonnull
    public static IDetectionRule<AstNode> rsaPaddingRule() {
        return EVP_PKEY_CTX_SET_RSA_PADDING;
    }

    /**
     * The rules for the calls that select a cipher, for functions that take the cipher as an
     * argument.
     */
    @Nonnull
    public static List<IDetectionRule<AstNode>> cipherSelectionRules() {
        return CIPHER_SELECTION;
    }
}
