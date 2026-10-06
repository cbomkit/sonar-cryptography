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
package com.ibm.plugin.rules.detection.pycrypto.cipher;

import static com.ibm.engine.detection.MethodMatcher.ANY;

import com.ibm.engine.model.CipherAction;
import com.ibm.engine.model.context.CipherContext;
import com.ibm.engine.model.factory.AlgorithmFactory;
import com.ibm.engine.model.factory.CipherActionFactory;
import com.ibm.engine.model.factory.ModeFactory;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.DetectionRuleSet;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.RuleSets;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.plugin.rules.detection.pycrypto.publickey.PythonCryptoRSA;
import java.util.List;
import java.util.Map;
import javax.annotation.Nonnull;
import org.sonar.plugins.python.api.tree.Tree;

@SuppressWarnings("java:S1192")
public final class PythonCryptoCipher extends DetectionRuleSet<Tree> {

    private PythonCryptoCipher() {
        // private
    }

    private static final IDetectionRule<Tree> ENCRYPT =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(ANY)
                    .forMethods("encrypt", "encrypt_and_digest")
                    .shouldBeDetectedAs(new CipherActionFactory<>(CipherAction.Action.ENCRYPT))
                    .withMethodParameter(ANY)
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "PyCrypto")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> DECRYPT =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(ANY)
                    .forMethods("decrypt", "decrypt_and_verify")
                    .shouldBeDetectedAs(new CipherActionFactory<>(CipherAction.Action.DECRYPT))
                    .withMethodParameter(ANY)
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "PyCrypto")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> AES =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("Crypto.Cipher.AES", "Cryptodome.Cipher.AES")
                    .forMethods("new")
                    .shouldBeDetectedAs(new ValueActionFactory<>("AES"))
                    .withNamedMethodParameter("key", ANY)
                    .withNamedMethodParameter(
                            "mode", ANY) // Crypto.Cipher.AES.* or Cryptodome.Cipher.AES.*
                    .shouldBeDetectedAs(new ModeFactory<>())
                    .asChildOfParameterWithId(-1)
                    .withOptionalNamedMethodParameter("iv", ANY)
                    .withOptionalNamedMethodParameter("nonce", ANY)
                    .withOptionalNamedMethodParameter("segment_size", "int")
                    .withOptionalNamedMethodParameter("mac_len", "int")
                    .withOptionalNamedMethodParameter("msg_len", "int")
                    .withOptionalNamedMethodParameter("assoc_len", "int")
                    .withOptionalNamedMethodParameter("initial_value", ANY)
                    .withOptionalNamedMethodParameter("counter", ANY)
                    .withOptionalNamedMethodParameter("use_aesni", ANY)
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "PyCrypto")
                    .withDependingDetectionRules(List.of(ENCRYPT, DECRYPT));

    private static final IDetectionRule<Tree> DES =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("Crypto.Cipher.DES", "Cryptodome.Cipher.DES")
                    .forMethods("new")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DES"))
                    .withNamedMethodParameter("key", ANY)
                    .withNamedMethodParameter(
                            "mode", ANY) // Crypto.Cipher.DES.* or Cryptodome.Cipher.DES.*
                    .shouldBeDetectedAs(new ModeFactory<>())
                    .asChildOfParameterWithId(-1)
                    .withOptionalNamedMethodParameter("iv", ANY)
                    .withOptionalNamedMethodParameter("nonce", ANY)
                    .withOptionalNamedMethodParameter("segment_size", "int")
                    .withOptionalNamedMethodParameter("mac_len", "int")
                    .withOptionalNamedMethodParameter("initial_value", "int")
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "PyCrypto")
                    .withDependingDetectionRules(List.of(ENCRYPT, DECRYPT));

    private static final IDetectionRule<Tree> DES3 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("Crypto.Cipher.DES3", "Cryptodome.Cipher.DES3")
                    .forMethods("new")
                    .shouldBeDetectedAs(new ValueActionFactory<>("3DES"))
                    .withNamedMethodParameter("key", ANY)
                    .withNamedMethodParameter(
                            "mode", ANY) // Crypto.Cipher.DES3.* or Cryptodome.Cipher.DES3.*
                    .shouldBeDetectedAs(new ModeFactory<>())
                    .asChildOfParameterWithId(-1)
                    .withOptionalNamedMethodParameter("iv", ANY)
                    .withOptionalNamedMethodParameter("nonce", ANY)
                    .withOptionalNamedMethodParameter("segment_size", "int")
                    .withOptionalNamedMethodParameter("mac_len", "int")
                    .withOptionalNamedMethodParameter("initial_value", "int")
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "PyCrypto")
                    .withDependingDetectionRules(List.of(ENCRYPT, DECRYPT));

    private static final IDetectionRule<Tree> BLOWFISH =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("Crypto.Cipher.Blowfish", "Cryptodome.Cipher.Blowfish")
                    .forMethods("new")
                    .shouldBeDetectedAs(new ValueActionFactory<>("Blowfish"))
                    .withNamedMethodParameter("key", ANY)
                    .withNamedMethodParameter(
                            "mode", ANY) // Crypto.Cipher.Blowfish.* or Cryptodome.Cipher.Blowfish.*
                    .shouldBeDetectedAs(new ModeFactory<>())
                    .asChildOfParameterWithId(-1)
                    .withOptionalNamedMethodParameter("iv", ANY)
                    .withOptionalNamedMethodParameter("nonce", ANY)
                    .withOptionalNamedMethodParameter("segment_size", "int")
                    .withOptionalNamedMethodParameter("mac_len", "int")
                    .withOptionalNamedMethodParameter("initial_value", "int")
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "PyCrypto")
                    .withDependingDetectionRules(List.of(ENCRYPT, DECRYPT));

    private static final IDetectionRule<Tree> CAST =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("Crypto.Cipher.CAST", "Cryptodome.Cipher.CAST")
                    .forMethods("new")
                    .shouldBeDetectedAs(new ValueActionFactory<>("CAST5"))
                    .withNamedMethodParameter("key", ANY)
                    .withNamedMethodParameter(
                            "mode", ANY) // Crypto.Cipher.CAST.* or Cryptodome.Cipher.CAST.*
                    .shouldBeDetectedAs(new ModeFactory<>())
                    .asChildOfParameterWithId(-1)
                    .withOptionalNamedMethodParameter("iv", ANY)
                    .withOptionalNamedMethodParameter("nonce", ANY)
                    .withOptionalNamedMethodParameter("segment_size", "int")
                    .withOptionalNamedMethodParameter("mac_len", "int")
                    .withOptionalNamedMethodParameter("initial_value", "int")
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "PyCrypto")
                    .withDependingDetectionRules(List.of(ENCRYPT, DECRYPT));

    private static final IDetectionRule<Tree> ARC2 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("Crypto.Cipher.ARC2", "Cryptodome.Cipher.ARC2")
                    .forMethods("new")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RC2"))
                    .withNamedMethodParameter("key", ANY)
                    .withNamedMethodParameter(
                            "mode", ANY) // Crypto.Cipher.ARC2.* or Cryptodome.Cipher.ARC2.*
                    .shouldBeDetectedAs(new ModeFactory<>())
                    .asChildOfParameterWithId(-1)
                    .withOptionalNamedMethodParameter("iv", ANY)
                    .withOptionalNamedMethodParameter("nonce", ANY)
                    .withOptionalNamedMethodParameter("effective_keylen", "int")
                    .withOptionalNamedMethodParameter("segment_size", "int")
                    .withOptionalNamedMethodParameter("mac_len", "int")
                    .withOptionalNamedMethodParameter("initial_value", "int")
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "PyCrypto")
                    .withDependingDetectionRules(List.of(ENCRYPT, DECRYPT));

    private static final IDetectionRule<Tree> ARC4 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("Crypto.Cipher.ARC4", "Cryptodome.Cipher.ARC4")
                    .forMethods("new")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RC4"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext(Map.of("algorithm", "RC4")))
                    .inBundle(() -> "PyCrypto")
                    .withDependingDetectionRules(List.of(ENCRYPT, DECRYPT));

    private static final IDetectionRule<Tree> CHACHA20 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("Crypto.Cipher.ChaCha20", "Cryptodome.Cipher.ChaCha20")
                    .forMethods("new")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ChaCha20"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "PyCrypto")
                    .withDependingDetectionRules(List.of(ENCRYPT, DECRYPT));

    private static final IDetectionRule<Tree> CHACHA20_POLY1305 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(
                            "Crypto.Cipher.ChaCha20_Poly1305",
                            "Cryptodome.Cipher.ChaCha20_Poly1305")
                    .forMethods("new")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ChaCha20Poly1305"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "PyCrypto")
                    .withDependingDetectionRules(List.of(ENCRYPT, DECRYPT));

    private static final IDetectionRule<Tree> SALSA20 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("Crypto.Cipher.Salsa20", "Cryptodome.Cipher.Salsa20")
                    .forMethods("new")
                    .shouldBeDetectedAs(new ValueActionFactory<>("Salsa20"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "PyCrypto")
                    .withDependingDetectionRules(List.of(ENCRYPT, DECRYPT));

    private static final IDetectionRule<Tree> PKCS1_OAEP =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectExactTypes("Crypto.Cipher.PKCS1_OAEP", "Cryptodome.Cipher.PKCS1_OAEP")
                    .forMethods("new")
                    .shouldBeDetectedAs(new ValueActionFactory<>("PKCS1_OAEP"))
                    .withMethodParameter(
                            ANY) // Crypto.PublicKey.RSAkey or Cryptodome.PublicKey.RSAkey
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .asChildOfParameterWithId(-1)
                    .addDependingDetectionRules(RuleSets.rulesOf(PythonCryptoRSA.class))
                    .withOptionalNamedMethodParameter("hashAlgo", ANY)
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .asChildOfParameterWithId(-1)
                    .withOptionalNamedMethodParameter("mgfunc", ANY)
                    .withOptionalNamedMethodParameter("label", ANY)
                    .withOptionalNamedMethodParameter("randfunc", ANY)
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "PyCrypto")
                    .withDependingDetectionRules(List.of(ENCRYPT, DECRYPT));

    private static final IDetectionRule<Tree> PKCS1_V1_5 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectExactTypes("Crypto.Cipher.PKCS1_v1_5", "Cryptodome.Cipher.PKCS1_v1_5")
                    .forMethods("new")
                    .shouldBeDetectedAs(new ValueActionFactory<>("PKCS1_v1_5"))
                    .withMethodParameter(
                            ANY) // Crypto.PublicKey.RSAkey or Cryptodome.PublicKey.RSAkey
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .asChildOfParameterWithId(-1)
                    .addDependingDetectionRules(RuleSets.rulesOf(PythonCryptoRSA.class))
                    .withOptionalNamedMethodParameter("randfunc", ANY)
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "PyCrypto")
                    .withDependingDetectionRules(List.of(ENCRYPT, DECRYPT));

    @Nonnull
    @Override
    protected List<IDetectionRule<Tree>> buildRules() {
        return List.of(
                AES,
                DES,
                DES3,
                BLOWFISH,
                CAST,
                ARC2,
                ARC4,
                CHACHA20,
                CHACHA20_POLY1305,
                SALSA20,
                PKCS1_OAEP,
                PKCS1_V1_5);
    }
}
