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
package com.ibm.plugin.rules.detection.openssl.kdf;

import com.ibm.engine.model.Size;
import com.ibm.engine.model.context.CipherContext;
import com.ibm.engine.model.context.KeyDerivationFunctionContext;
import com.ibm.engine.model.factory.IterationCountFactory;
import com.ibm.engine.model.factory.SaltSizeFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.plugin.rules.detection.Memoize;
import com.ibm.plugin.rules.detection.openssl.cipher.OpenSSLCipherOperationFactory;
import com.ibm.plugin.rules.detection.openssl.cipher.OpenSSLEvpCipher;
import com.ibm.plugin.rules.detection.openssl.legacy.OpenSSLNidLookupFactory;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.List;
import java.util.function.Supplier;
import javax.annotation.Nonnull;

/**
 * Detection rules for password-based encryption selected by its algorithm identifier: {@code
 * PKCS8_encrypt}, which encrypts a PKCS#8 private key with the scheme of {@code pbe_nid} (PBES2
 * with {@code cipher} for -1), and {@code EVP_PBE_CipherInit}, which initializes a cipher context
 * with the scheme of an {@code OBJ_nid2obj} object, for the operation given by {@code en_de}.
 */
@SuppressWarnings("java:S1192")
public final class OpenSSLPasswordBasedEncryption {

    private static final String BUNDLE = "OpenSSL";

    private static final OpenSSLNidLookupFactory PBE_ALGORITHM =
            new OpenSSLNidLookupFactory(
                    OpenSSLNidLookupFactory.PBE_ALGORITHM_BY_CODE,
                    OpenSSLNidLookupFactory.PBE_ALGORITHM_BY_NAME);

    // PKCS8_encrypt(pbe_nid, cipher, pass, passlen, salt, saltlen, iter, p8inf)
    private static final IDetectionRule<AstNode> PKCS8_ENCRYPT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("PKCS8_encrypt")
                    .withMethodParameter("*") // pbe_nid
                    .shouldBeDetectedAs(PBE_ALGORITHM)
                    .withMethodParameter("*") // cipher
                    .addDependingDetectionRules(OpenSSLEvpCipher.cipherSelectionRules())
                    .withMethodParameter("*") // pass
                    .withMethodParameter("*") // passlen
                    .withMethodParameter("*") // salt
                    .withMethodParameter("*") // saltlen
                    .shouldBeDetectedAs(new SaltSizeFactory<>(Size.UnitType.BYTE))
                    .asChildOfParameterWithId(0)
                    .withMethodParameter("*") // iter
                    .shouldBeDetectedAs(new IterationCountFactory<>())
                    .asChildOfParameterWithId(0)
                    .withMethodParameter("*") // p8inf
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // PKCS8_encrypt_ex(pbe_nid, cipher, pass, passlen, salt, saltlen, iter, p8inf, libctx, propq)
    private static final IDetectionRule<AstNode> PKCS8_ENCRYPT_EX =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("PKCS8_encrypt_ex")
                    .withMethodParameter("*") // pbe_nid
                    .shouldBeDetectedAs(PBE_ALGORITHM)
                    .withMethodParameter("*") // cipher
                    .addDependingDetectionRules(OpenSSLEvpCipher.cipherSelectionRules())
                    .withMethodParameter("*") // pass
                    .withMethodParameter("*") // passlen
                    .withMethodParameter("*") // salt
                    .withMethodParameter("*") // saltlen
                    .shouldBeDetectedAs(new SaltSizeFactory<>(Size.UnitType.BYTE))
                    .asChildOfParameterWithId(0)
                    .withMethodParameter("*") // iter
                    .shouldBeDetectedAs(new IterationCountFactory<>())
                    .asChildOfParameterWithId(0)
                    .withMethodParameter("*") // p8inf
                    .withMethodParameter("*") // libctx
                    .withMethodParameter("*") // propq
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // OBJ_nid2obj(nid): the object identifying the scheme given to EVP_PBE_CipherInit
    private static final IDetectionRule<AstNode> OBJ_NID2OBJ =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("OBJ_nid2obj")
                    .withMethodParameter("*")
                    .shouldBeDetectedAs(PBE_ALGORITHM)
                    .buildForContext(new KeyDerivationFunctionContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // EVP_PBE_CipherInit(pbe_obj, pass, passlen, param, ctx, en_de): initializes the cipher context
    // with the cipher of the scheme and the key derived from the password; en_de 1 encrypts, 0
    // decrypts
    private static final IDetectionRule<AstNode> EVP_PBE_CIPHER_INIT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PBE_CipherInit")
                    .withMethodParameter("*") // pbe_obj
                    .addDependingDetectionRules(List.of(OBJ_NID2OBJ))
                    .withMethodParameter("*") // pass
                    .withMethodParameter("*") // passlen
                    .withMethodParameter("*") // param
                    .withMethodParameter("*") // ctx
                    .withMethodParameter("*") // en_de
                    .shouldBeDetectedAs(new OpenSSLCipherOperationFactory())
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    // EVP_PBE_CipherInit_ex(pbe_obj, pass, passlen, param, ctx, en_de, libctx, propq)
    private static final IDetectionRule<AstNode> EVP_PBE_CIPHER_INIT_EX =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PBE_CipherInit_ex")
                    .withMethodParameter("*") // pbe_obj
                    .addDependingDetectionRules(List.of(OBJ_NID2OBJ))
                    .withMethodParameter("*") // pass
                    .withMethodParameter("*") // passlen
                    .withMethodParameter("*") // param
                    .withMethodParameter("*") // ctx
                    .withMethodParameter("*") // en_de
                    .shouldBeDetectedAs(new OpenSSLCipherOperationFactory())
                    .withMethodParameter("*") // libctx
                    .withMethodParameter("*") // propq
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private OpenSSLPasswordBasedEncryption() {
        // private
    }

    private static final Supplier<List<IDetectionRule<AstNode>>> RULES =
            Memoize.of(
                    () ->
                            List.of(
                                    PKCS8_ENCRYPT,
                                    PKCS8_ENCRYPT_EX,
                                    EVP_PBE_CIPHER_INIT,
                                    EVP_PBE_CIPHER_INIT_EX));

    @Nonnull
    public static List<IDetectionRule<AstNode>> rules() {
        return RULES.get();
    }
}
