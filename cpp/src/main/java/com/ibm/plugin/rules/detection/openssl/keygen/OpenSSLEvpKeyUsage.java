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
package com.ibm.plugin.rules.detection.openssl.keygen;

import com.ibm.engine.language.cxx.CxxLanguageTranslation;
import com.ibm.engine.model.CipherAction;
import com.ibm.engine.model.KeyAction;
import com.ibm.engine.model.SignatureAction;
import com.ibm.engine.model.context.CipherContext;
import com.ibm.engine.model.context.IDetectionContext;
import com.ibm.engine.model.context.KeyContext;
import com.ibm.engine.model.context.SignatureContext;
import com.ibm.engine.model.factory.CipherActionFactory;
import com.ibm.engine.model.factory.IActionFactory;
import com.ibm.engine.model.factory.KeyActionFactory;
import com.ibm.engine.model.factory.SignatureActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.plugin.rules.detection.openssl.cipher.OpenSSLEvpCipher;
import com.ibm.plugin.rules.detection.openssl.digest.OpenSSLEvpMessageDigest;
import com.ibm.plugin.rules.detection.openssl.digest.OpenSSLNameCanonicalizerFactory;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import java.util.stream.Stream;
import javax.annotation.Nonnull;

/**
 * Detection rules for the operations performed with an OpenSSL key ({@code EVP_PKEY}). They are
 * depending rules of the calls that generate the key (see {@link OpenSSLEvpKeyGen}), so that each
 * operation is reported on the key it uses, as the key's algorithm is what selects the operation's
 * algorithm:
 *
 * <pre>{@code
 * EVP_PKEY *pkey = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256");
 * EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, pkey); // ECDSA with SHA-256
 *
 * EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
 * EVP_PKEY_derive_init(ctx);                                 // ECDH
 * }</pre>
 *
 * <p>The operations are the signature and its verification, key agreement ({@code
 * EVP_PKEY_derive}), public-key encryption and decryption, and key encapsulation, together with the
 * digest and the RSA padding they use; the signature of certificates, certificate requests and CRLs
 * ({@code X509_sign}, ...) and their verification, the CMS, PKCS#7 and OCSP signatures ({@code
 * CMS_sign}, {@code PKCS7_sign}, {@code OCSP_basic_sign}, ...), and the encryption and decryption
 * of the session key of an envelope ({@code EVP_SealInit} / {@code EVP_OpenInit}). The {@code
 * X509_sign_ctx} forms sign with a context initialized by {@code EVP_DigestSignInit}, which is
 * where the key and the digest are reported.
 */
public final class OpenSSLEvpKeyUsage {

    private static final String BUNDLE = "OpenSSL";

    private static final SignatureAction.Action SIGN = SignatureAction.Action.SIGN;
    private static final SignatureAction.Action VERIFY = SignatureAction.Action.VERIFY;

    /** The digest index of an operation given no digest. */
    private static final int NO_DIGEST = -1;

    // Operations on a context created for the key: the init function of each operation, one rule
    // per number of arguments, e.g. EVP_PKEY_sign_init(ctx), EVP_PKEY_sign_init_ex(ctx, params) and
    // EVP_PKEY_sign_init_ex2(ctx, algo, params)

    private static final List<IDetectionRule<AstNode>> EVP_PKEY_SIGN =
            operationInit(
                    new SignatureActionFactory<>(SignatureAction.Action.SIGN),
                    SignatureContext::new,
                    new InitFunctions(1, "EVP_PKEY_sign_init"),
                    new InitFunctions(2, "EVP_PKEY_sign_init_ex"),
                    new InitFunctions(3, "EVP_PKEY_sign_init_ex2", "EVP_PKEY_sign_message_init"));

    private static final List<IDetectionRule<AstNode>> EVP_PKEY_VERIFY =
            operationInit(
                    new SignatureActionFactory<>(SignatureAction.Action.VERIFY),
                    SignatureContext::new,
                    new InitFunctions(1, "EVP_PKEY_verify_init", "EVP_PKEY_verify_recover_init"),
                    new InitFunctions(
                            2, "EVP_PKEY_verify_init_ex", "EVP_PKEY_verify_recover_init_ex"),
                    new InitFunctions(
                            3,
                            "EVP_PKEY_verify_init_ex2",
                            "EVP_PKEY_verify_message_init",
                            "EVP_PKEY_verify_recover_init_ex2"));

    private static final List<IDetectionRule<AstNode>> EVP_PKEY_ENCRYPT =
            operationInit(
                    new CipherActionFactory<>(CipherAction.Action.ENCRYPT),
                    CipherContext::new,
                    new InitFunctions(1, "EVP_PKEY_encrypt_init"),
                    new InitFunctions(2, "EVP_PKEY_encrypt_init_ex"));

    private static final List<IDetectionRule<AstNode>> EVP_PKEY_DECRYPT =
            operationInit(
                    new CipherActionFactory<>(CipherAction.Action.DECRYPT),
                    CipherContext::new,
                    new InitFunctions(1, "EVP_PKEY_decrypt_init"),
                    new InitFunctions(2, "EVP_PKEY_decrypt_init_ex"));

    private static final List<IDetectionRule<AstNode>> EVP_PKEY_DERIVE =
            operationInit(
                    new KeyActionFactory<>(KeyAction.Action.KDF),
                    KeyContext::new,
                    new InitFunctions(1, "EVP_PKEY_derive_init"),
                    new InitFunctions(2, "EVP_PKEY_derive_init_ex"));

    // EVP_PKEY_encapsulate_init(ctx, params), EVP_PKEY_auth_encapsulate_init(ctx, authpriv, params)
    private static final List<IDetectionRule<AstNode>> EVP_PKEY_ENCAPSULATE =
            operationInit(
                    new KeyActionFactory<>(KeyAction.Action.ENCAPSULATION),
                    KeyContext::new,
                    new InitFunctions(2, "EVP_PKEY_encapsulate_init"),
                    new InitFunctions(3, "EVP_PKEY_auth_encapsulate_init"));

    private static final List<IDetectionRule<AstNode>> EVP_PKEY_DECAPSULATE =
            operationInit(
                    new KeyActionFactory<>(KeyAction.Action.DECAPSULATION),
                    KeyContext::new,
                    new InitFunctions(2, "EVP_PKEY_decapsulate_init"),
                    new InitFunctions(3, "EVP_PKEY_auth_decapsulate_init"));

    /** Init functions of an operation that take the same number of arguments. */
    private record InitFunctions(int parameterCount, @Nonnull List<String> names) {
        InitFunctions(int parameterCount, @Nonnull String... names) {
            this(parameterCount, List.of(names));
        }
    }

    @Nonnull
    private static List<IDetectionRule<AstNode>> operationInit(
            @Nonnull IActionFactory<AstNode> operation,
            @Nonnull Supplier<IDetectionContext> context,
            @Nonnull InitFunctions... initFunctions) {
        return Stream.of(initFunctions)
                .map(
                        functions -> {
                            IDetectionRule.ParametersFactoryBuilder<AstNode> parameters =
                                    new DetectionRuleBuilder<AstNode>()
                                            .createDetectionRule()
                                            .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                                            .forMethods(functions.names().toArray(new String[0]))
                                            .shouldBeDetectedAs(operation)
                                            .withMethodParameter("*");
                            for (int i = 1; i < functions.parameterCount(); i++) {
                                parameters = parameters.withMethodParameter("*");
                            }
                            return parameters
                                    .buildForContext(context.get())
                                    .inBundle(() -> BUNDLE)
                                    .withoutDependingDetectionRules();
                        })
                .toList();
    }

    /** The operations, and the RSA padding, set on a context created for the key. */
    private static final List<IDetectionRule<AstNode>> KEY_CONTEXT_OPERATIONS =
            Stream.of(
                            EVP_PKEY_SIGN,
                            EVP_PKEY_VERIFY,
                            EVP_PKEY_ENCRYPT,
                            EVP_PKEY_DECRYPT,
                            EVP_PKEY_DERIVE,
                            EVP_PKEY_ENCAPSULATE,
                            EVP_PKEY_DECAPSULATE,
                            List.of(OpenSSLEvpCipher.rsaPaddingRule()))
                    .flatMap(List::stream)
                    .toList();

    // Uses of the key: a context created for it, or a digest sign or verify operation with it

    // EVP_PKEY_CTX_new(pkey, e)
    private static final IDetectionRule<AstNode> EVP_PKEY_CTX_NEW =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                    .forMethods("EVP_PKEY_CTX_new")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .buildForContext(new KeyContext())
                    .inBundle(() -> BUNDLE)
                    .withDependingDetectionRules(KEY_CONTEXT_OPERATIONS);

    // EVP_PKEY_CTX_new_from_pkey(libctx, pkey, propq)
    private static final IDetectionRule<AstNode> EVP_PKEY_CTX_NEW_FROM_PKEY =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                    .forMethods("EVP_PKEY_CTX_new_from_pkey")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .withMethodParameter("*")
                    .buildForContext(new KeyContext())
                    .inBundle(() -> BUNDLE)
                    .withDependingDetectionRules(KEY_CONTEXT_OPERATIONS);

    /** The RSA padding set on the context a digest sign or verify operation returns in pctx. */
    private static final List<IDetectionRule<AstNode>> SIGNING_CONTEXT_SETTINGS =
            List.of(OpenSSLEvpCipher.rsaPaddingRule());

    // EVP_DigestSignInit(mdctx, pctx, md, e, pkey) / EVP_DigestVerifyInit(...)
    private static final IDetectionRule<AstNode> EVP_DIGEST_SIGN_INIT =
            digestSignInit("EVP_DigestSignInit", SignatureAction.Action.SIGN);

    private static final IDetectionRule<AstNode> EVP_DIGEST_VERIFY_INIT =
            digestSignInit("EVP_DigestVerifyInit", SignatureAction.Action.VERIFY);

    // EVP_DigestSignInit_ex(mdctx, pctx, mdname, libctx, props, pkey, params) /
    // EVP_DigestVerifyInit_ex(...): the digest is given by name
    private static final IDetectionRule<AstNode> EVP_DIGEST_SIGN_INIT_EX =
            digestSignInitEx("EVP_DigestSignInit_ex", SignatureAction.Action.SIGN);

    private static final IDetectionRule<AstNode> EVP_DIGEST_VERIFY_INIT_EX =
            digestSignInitEx("EVP_DigestVerifyInit_ex", SignatureAction.Action.VERIFY);

    @Nonnull
    private static IDetectionRule<AstNode> digestSignInit(
            @Nonnull String function, @Nonnull SignatureAction.Action action) {
        return new DetectionRuleBuilder<AstNode>()
                .createDetectionRule()
                .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                .forMethods(function)
                .shouldBeDetectedAs(new SignatureActionFactory<>(action))
                .withMethodParameter("*")
                .withMethodParameter("*")
                .withMethodParameter("*")
                .addDependingDetectionRules(OpenSSLEvpMessageDigest.rules())
                .withMethodParameter("*")
                .withMethodParameter("*")
                .buildForContext(new SignatureContext())
                .inBundle(() -> BUNDLE)
                .withDependingDetectionRules(SIGNING_CONTEXT_SETTINGS);
    }

    @Nonnull
    private static IDetectionRule<AstNode> digestSignInitEx(
            @Nonnull String function, @Nonnull SignatureAction.Action action) {
        return new DetectionRuleBuilder<AstNode>()
                .createDetectionRule()
                .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                .forMethods(function)
                .shouldBeDetectedAs(new SignatureActionFactory<>(action))
                .withMethodParameter("*")
                .withMethodParameter("*")
                .withMethodParameter("*")
                .shouldBeDetectedAs(
                        new OpenSSLNameCanonicalizerFactory(
                                OpenSSLNameCanonicalizerFactory.DIGEST_NAMES))
                .asChildOfParameterWithId(-1)
                .withMethodParameter("*")
                .withMethodParameter("*")
                .withMethodParameter("*")
                .withMethodParameter("*")
                .buildForContext(new SignatureContext(Map.of("kind", "DIGEST_NAME")))
                .inBundle(() -> BUNDLE)
                .withDependingDetectionRules(SIGNING_CONTEXT_SETTINGS);
    }

    // Operations taking the key as an argument, with the digest they use where they are given one

    // X509_sign(x, pkey, md), X509_REQ_sign(req, pkey, md), X509_CRL_sign(crl, pkey, md)
    private static final IDetectionRule<AstNode> X509_SIGN =
            keyOperation(SIGN, 3, 2, "X509_sign", "X509_REQ_sign", "X509_CRL_sign");

    // X509_verify(x, pkey), X509_REQ_verify(req, pkey), X509_CRL_verify(crl, pkey)
    private static final IDetectionRule<AstNode> X509_VERIFY =
            keyOperation(VERIFY, 2, NO_DIGEST, "X509_verify", "X509_REQ_verify", "X509_CRL_verify");

    // X509_REQ_verify_ex(req, pkey, libctx, propq)
    private static final IDetectionRule<AstNode> X509_REQ_VERIFY_EX =
            keyOperation(VERIFY, 4, NO_DIGEST, "X509_REQ_verify_ex");

    // CMS_sign(signcert, pkey, certs, data, flags), PKCS7_sign(...): the default digest
    private static final IDetectionRule<AstNode> CMS_SIGN =
            keyOperation(SIGN, 5, NO_DIGEST, "CMS_sign", "PKCS7_sign");

    // CMS_sign_ex(signcert, pkey, certs, data, flags, libctx, propq), PKCS7_sign_ex(...)
    private static final IDetectionRule<AstNode> CMS_SIGN_EX =
            keyOperation(SIGN, 7, NO_DIGEST, "CMS_sign_ex", "PKCS7_sign_ex");

    // CMS_add1_signer(cms, signer, pkey, md, flags), PKCS7_sign_add_signer(p7, signcert, pkey,
    // md, flags)
    private static final IDetectionRule<AstNode> CMS_ADD_SIGNER =
            keyOperation(SIGN, 5, 3, "CMS_add1_signer", "PKCS7_sign_add_signer");

    // OCSP_basic_sign(brsp, signer, key, dgst, certs, flags)
    private static final IDetectionRule<AstNode> OCSP_BASIC_SIGN =
            keyOperation(SIGN, 6, 3, "OCSP_basic_sign");

    // EVP_SealInit(ctx, type, ek, ekl, iv, pubk, npubk): the session key is encrypted with the
    // public keys; EVP_OpenInit(ctx, type, ek, ekl, iv, priv) decrypts it with the private key
    private static final IDetectionRule<AstNode> EVP_SEAL_INIT =
            keyOperation(
                    new CipherActionFactory<>(CipherAction.Action.ENCRYPT),
                    new CipherContext(),
                    7,
                    NO_DIGEST,
                    "EVP_SealInit");

    private static final IDetectionRule<AstNode> EVP_OPEN_INIT =
            keyOperation(
                    new CipherActionFactory<>(CipherAction.Action.DECRYPT),
                    new CipherContext(),
                    6,
                    NO_DIGEST,
                    "EVP_OpenInit");

    @Nonnull
    private static IDetectionRule<AstNode> keyOperation(
            @Nonnull SignatureAction.Action action,
            int parameterCount,
            int digestIndex,
            @Nonnull String... functions) {
        return keyOperation(
                new SignatureActionFactory<>(action),
                new SignatureContext(),
                parameterCount,
                digestIndex,
                functions);
    }

    /**
     * An operation taking the key as an argument, detected as {@code operation}; the digest given
     * at {@code digestIndex} ({@link #NO_DIGEST} for none) is traced back to where it is selected.
     */
    @Nonnull
    private static IDetectionRule<AstNode> keyOperation(
            @Nonnull IActionFactory<AstNode> operation,
            @Nonnull IDetectionContext context,
            int parameterCount,
            int digestIndex,
            @Nonnull String... functions) {
        IDetectionRule.ParametersFactoryBuilder<AstNode> parameters =
                new DetectionRuleBuilder<AstNode>()
                        .createDetectionRule()
                        .forObjectTypes(CxxLanguageTranslation.GLOBAL_SCOPE)
                        .forMethods(functions)
                        .shouldBeDetectedAs(operation)
                        .withMethodParameter("*");
        IDetectionRule.ParametersFinalDetectionRuleBuilder<AstNode> withDigest = null;
        for (int i = 1; i < parameterCount; i++) {
            parameters =
                    withDigest == null
                            ? parameters.withMethodParameter("*")
                            : withDigest.withMethodParameter("*");
            withDigest =
                    i == digestIndex
                            ? parameters.addDependingDetectionRules(OpenSSLEvpMessageDigest.rules())
                            : null;
        }
        return (withDigest == null
                        ? parameters.buildForContext(context)
                        : withDigest.buildForContext(context))
                .inBundle(() -> BUNDLE)
                .withoutDependingDetectionRules();
    }

    private OpenSSLEvpKeyUsage() {
        // private
    }

    /** The uses of a key, followed from the variable holding it. */
    @Nonnull
    static List<IDetectionRule<AstNode>> rules() {
        return List.of(
                EVP_PKEY_CTX_NEW,
                EVP_PKEY_CTX_NEW_FROM_PKEY,
                EVP_DIGEST_SIGN_INIT,
                EVP_DIGEST_VERIFY_INIT,
                EVP_DIGEST_SIGN_INIT_EX,
                EVP_DIGEST_VERIFY_INIT_EX,
                X509_SIGN,
                X509_VERIFY,
                X509_REQ_VERIFY_EX,
                CMS_SIGN,
                CMS_SIGN_EX,
                CMS_ADD_SIGNER,
                OCSP_BASIC_SIGN,
                EVP_SEAL_INIT,
                EVP_OPEN_INIT);
    }
}
