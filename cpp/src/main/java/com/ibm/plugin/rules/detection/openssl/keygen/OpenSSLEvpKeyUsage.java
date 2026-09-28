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

import com.ibm.engine.model.CipherAction;
import com.ibm.engine.model.KeyAction;
import com.ibm.engine.model.SignatureAction;
import com.ibm.engine.model.context.CipherContext;
import com.ibm.engine.model.context.KeyContext;
import com.ibm.engine.model.context.SignatureContext;
import com.ibm.engine.model.factory.CipherActionFactory;
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
 * digest and the RSA padding they use.
 */
public final class OpenSSLEvpKeyUsage {

    private static final String BUNDLE = "OpenSSL";

    // Operations on a context created for the key

    private static final IDetectionRule<AstNode> EVP_PKEY_SIGN =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods(
                            "EVP_PKEY_sign_init",
                            "EVP_PKEY_sign_init_ex",
                            "EVP_PKEY_sign_init_ex2",
                            "EVP_PKEY_sign_message_init")
                    .shouldBeDetectedAs(new SignatureActionFactory<>(SignatureAction.Action.SIGN))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_PKEY_VERIFY =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods(
                            "EVP_PKEY_verify_init",
                            "EVP_PKEY_verify_init_ex",
                            "EVP_PKEY_verify_init_ex2",
                            "EVP_PKEY_verify_message_init",
                            "EVP_PKEY_verify_recover_init",
                            "EVP_PKEY_verify_recover_init_ex",
                            "EVP_PKEY_verify_recover_init_ex2")
                    .shouldBeDetectedAs(new SignatureActionFactory<>(SignatureAction.Action.VERIFY))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_PKEY_ENCRYPT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_encrypt_init", "EVP_PKEY_encrypt_init_ex")
                    .shouldBeDetectedAs(new CipherActionFactory<>(CipherAction.Action.ENCRYPT))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_PKEY_DECRYPT =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_decrypt_init", "EVP_PKEY_decrypt_init_ex")
                    .shouldBeDetectedAs(new CipherActionFactory<>(CipherAction.Action.DECRYPT))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_PKEY_DERIVE =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_derive_init", "EVP_PKEY_derive_init_ex")
                    .shouldBeDetectedAs(new KeyActionFactory<>(KeyAction.Action.KDF))
                    .withAnyParameters()
                    .buildForContext(new KeyContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_PKEY_ENCAPSULATE =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_encapsulate_init", "EVP_PKEY_auth_encapsulate_init")
                    .shouldBeDetectedAs(new KeyActionFactory<>(KeyAction.Action.ENCAPSULATION))
                    .withAnyParameters()
                    .buildForContext(new KeyContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<AstNode> EVP_PKEY_DECAPSULATE =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
                    .forMethods("EVP_PKEY_decapsulate_init", "EVP_PKEY_auth_decapsulate_init")
                    .shouldBeDetectedAs(new KeyActionFactory<>(KeyAction.Action.DECAPSULATION))
                    .withAnyParameters()
                    .buildForContext(new KeyContext())
                    .inBundle(() -> BUNDLE)
                    .withoutDependingDetectionRules();

    /** The operations, and the RSA padding, set on a context created for the key. */
    private static final List<IDetectionRule<AstNode>> KEY_CONTEXT_OPERATIONS =
            List.of(
                    EVP_PKEY_SIGN,
                    EVP_PKEY_VERIFY,
                    EVP_PKEY_ENCRYPT,
                    EVP_PKEY_DECRYPT,
                    EVP_PKEY_DERIVE,
                    EVP_PKEY_ENCAPSULATE,
                    EVP_PKEY_DECAPSULATE,
                    OpenSSLEvpCipher.rsaPaddingRule());

    // Uses of the key: a context created for it, or a digest sign or verify operation with it

    // EVP_PKEY_CTX_new(pkey, e)
    private static final IDetectionRule<AstNode> EVP_PKEY_CTX_NEW =
            new DetectionRuleBuilder<AstNode>()
                    .createDetectionRule()
                    .forObjectTypes("*")
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
                    .forObjectTypes("*")
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
                .forObjectTypes("*")
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
                .forObjectTypes("*")
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
                EVP_DIGEST_VERIFY_INIT_EX);
    }
}
