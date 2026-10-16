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
package com.ibm.plugin.rules.detection.pycrypto.signature;

import static com.ibm.engine.detection.MethodMatcher.ANY;

import com.ibm.engine.model.KeyAction;
import com.ibm.engine.model.SignatureAction;
import com.ibm.engine.model.Size.UnitType;
import com.ibm.engine.model.context.PrivateKeyContext;
import com.ibm.engine.model.context.PublicKeyContext;
import com.ibm.engine.model.context.SignatureContext;
import com.ibm.engine.model.factory.AlgorithmFactory;
import com.ibm.engine.model.factory.KeyActionFactory;
import com.ibm.engine.model.factory.SaltSizeFactory;
import com.ibm.engine.model.factory.SignatureActionFactory;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.DetectionRuleSet;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.RuleSets;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.plugin.rules.detection.pycrypto.hash.PythonCryptoHash;
import com.ibm.plugin.rules.detection.pycrypto.publickey.PythonCryptoDSA;
import com.ibm.plugin.rules.detection.pycrypto.publickey.PythonCryptoECC;
import com.ibm.plugin.rules.detection.pycrypto.publickey.PythonCryptoRSA;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import javax.annotation.Nonnull;
import org.sonar.plugins.python.api.tree.Tree;

@SuppressWarnings("java:S1192")
public final class PythonCryptoSignature extends DetectionRuleSet<Tree> {

    private PythonCryptoSignature() {
        // private
    }

    private static final IDetectionRule<Tree> SIGN =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(ANY)
                    .forMethods("sign")
                    .shouldBeDetectedAs(new SignatureActionFactory<>(SignatureAction.Action.SIGN))
                    .withNamedMethodParameter("msg_hash", ANY) // Crypto.Hash.* or Cryptodome.Hash.*
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .asChildOfParameterWithId(-1)
                    .addDependingDetectionRules(RuleSets.rulesOf(PythonCryptoHash.class))
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> "PyCrypto")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> VERIFY =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(ANY)
                    .forMethods("verify")
                    .shouldBeDetectedAs(new SignatureActionFactory<>(SignatureAction.Action.VERIFY))
                    .withNamedMethodParameter("msg_hash", ANY) // Crypto.Hash.* or Cryptodome.Hash.*
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .asChildOfParameterWithId(-1)
                    .addDependingDetectionRules(RuleSets.rulesOf(PythonCryptoHash.class))
                    .withNamedMethodParameter("signature", ANY)
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> "PyCrypto")
                    .withoutDependingDetectionRules();

    // PSS signature scheme - sign and verify methods (called on the result of .new())
    private static final IDetectionRule<Tree> PKCS1V15 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("Crypto.Signature.pkcs1_15", "Cryptodome.Signature.pkcs1_15")
                    .forMethods("new")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RSA-PKCS1V15"))
                    .withNamedMethodParameter(
                            "rsa_key", ANY) // Crypto.PublicKey.RSA or Cryptodome.PublicKey.RSA
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .asChildOfParameterWithId(-1)
                    .addDependingDetectionRules(RuleSets.rulesOf(PythonCryptoRSA.class))
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> "PyCrypto")
                    .withDependingDetectionRules(List.of(SIGN, VERIFY));

    // PSS signature scheme - sign and verify methods (called on the result of .new())
    private static final IDetectionRule<Tree> PSS =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("Crypto.Signature.pss", "Cryptodome.Signature.pss")
                    .forMethods("new")
                    .shouldBeDetectedAs(new ValueActionFactory<>("RSA-PSS"))
                    .withNamedMethodParameter(
                            "rsa_key", ANY) // Crypto.PublicKey.RSA or Cryptodome.PublicKey.RSA
                    //    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .asChildOfParameterWithId(-1)
                    .addDependingDetectionRules(RuleSets.rulesOf(PythonCryptoRSA.class))
                    .withOptionalNamedMethodParameter("mask_func", ANY)
                    .withOptionalNamedMethodParameter("salt_bytes", "int")
                    .shouldBeDetectedAs(new SaltSizeFactory<>(UnitType.BYTE))
                    .asChildOfParameterWithId(-1)
                    .withOptionalNamedMethodParameter("rand_func", ANY)
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> "PyCrypto")
                    .withDependingDetectionRules(List.of(SIGN, VERIFY));

    // PSS signature scheme - sign and verify methods (called on the result of .new())
    private static final IDetectionRule<Tree> PSS_MGF1 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("Crypto.Signature.pss", "Cryptodome.Signature.pss")
                    .forMethods("MGF1")
                    .shouldBeDetectedAs(new ValueActionFactory<>("MGF1"))
                    .withNamedMethodParameter("mgfSeed", ANY)
                    .withNamedMethodParameter("maskLen", "int")
                    .withNamedMethodParameter("hash_gen", ANY) // Crypto.Hash.* or Cryptodome.Hash.*
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .asChildOfParameterWithId(-1)
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> "PyCrypto")
                    .withoutDependingDetectionRules();

    // DSS signature scheme - sign and verify methods (called on the result of .new())
    private static final IDetectionRule<Tree> DSS =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("Crypto.Signature.DSS")
                    .forMethods("new")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DSS"))
                    .withNamedMethodParameter("key", "Crypto.PublicKey.DSA")
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .asChildOfParameterWithId(-1)
                    .addDependingDetectionRules(RuleSets.rulesOf(PythonCryptoDSA.class))
                    .withNamedMethodParameter("mode", "str")
                    .withOptionalNamedMethodParameter("encoding", "str")
                    .withOptionalNamedMethodParameter("randfunc", ANY)
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> "PyCrypto")
                    .withDependingDetectionRules(List.of(SIGN, VERIFY));

    // DSS signature scheme - sign and verify methods (called on the result of .new())
    private static final IDetectionRule<Tree> DSS_CRYPTODOME =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("Cryptodome.Signature.DSS")
                    .forMethods("new")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DSS"))
                    .withNamedMethodParameter("key", "Cryptodome.PublicKey.DSA")
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .asChildOfParameterWithId(-1)
                    .addDependingDetectionRules(RuleSets.rulesOf(PythonCryptoDSA.class))
                    .withNamedMethodParameter("mode", "str")
                    .withOptionalNamedMethodParameter("encoding", "str")
                    .withOptionalNamedMethodParameter("randfunc", ANY)
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> "PyCrypto")
                    .withDependingDetectionRules(List.of(SIGN, VERIFY));

    // DSS signature scheme - sign and verify methods (called on the result of .new())
    private static final IDetectionRule<Tree> ECDSA =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("Crypto.Signature.DSS")
                    .forMethods("new")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ECDSA"))
                    .withNamedMethodParameter("key", "Crypto.PublicKey.ECC")
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .asChildOfParameterWithId(-1)
                    .addDependingDetectionRules(RuleSets.rulesOf(PythonCryptoECC.class))
                    .withNamedMethodParameter("mode", "str")
                    .withOptionalNamedMethodParameter("encoding", "str")
                    .withOptionalNamedMethodParameter("randfunc", ANY)
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> "PyCrypto")
                    .withDependingDetectionRules(List.of(SIGN, VERIFY));

    // DSS signature scheme - sign and verify methods (called on the result of .new())
    private static final IDetectionRule<Tree> ECDSA_CRYPTODOME =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("Cryptodome.Signature.DSS")
                    .forMethods("new")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ECDSA"))
                    .withNamedMethodParameter("key", "Cryptodome.PublicKey.ECC")
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .asChildOfParameterWithId(-1)
                    .addDependingDetectionRules(RuleSets.rulesOf(PythonCryptoECC.class))
                    .withNamedMethodParameter("mode", "str")
                    .withOptionalNamedMethodParameter("encoding", "str")
                    .withOptionalNamedMethodParameter("randfunc", ANY)
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> "PyCrypto")
                    .withDependingDetectionRules(List.of(SIGN, VERIFY));

    private static final IDetectionRule<Tree> EDDSA_SIGN =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(ANY)
                    .forMethods("sign")
                    .shouldBeDetectedAs(new SignatureActionFactory<>(SignatureAction.Action.SIGN))
                    .withNamedMethodParameter("msg_or_hash", ANY)
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> "PyCrypto")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> EDDSA_VERIFY =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(ANY)
                    .forMethods("verify")
                    .shouldBeDetectedAs(new SignatureActionFactory<>(SignatureAction.Action.VERIFY))
                    .withNamedMethodParameter("msg_or_hash", ANY)
                    .withNamedMethodParameter("signature", ANY)
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> "PyCrypto")
                    .withoutDependingDetectionRules();

    // EdDSA import private key
    private static final IDetectionRule<Tree> EDDSA_IMPORT_PRIVATE_KEY =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("Crypto.Signature.eddsa", "Cryptodome.Signature.eddsa")
                    .forMethods("import_private_key")
                    .shouldBeDetectedAs(
                            new KeyActionFactory<>(KeyAction.Action.PRIVATE_KEY_GENERATION))
                    .withAnyParameters()
                    .buildForContext(new PrivateKeyContext(Map.of("algorithm", "EC")))
                    .inBundle(() -> "PyCrypto")
                    .withoutDependingDetectionRules();

    // EdDSA import public key
    private static final IDetectionRule<Tree> EDDSA_IMPORT_PUBLIC_KEY =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("Crypto.Signature.eddsa", "Cryptodome.Signature.eddsa")
                    .forMethods("import_public_key")
                    .shouldBeDetectedAs(
                            new KeyActionFactory<>(KeyAction.Action.PUBLIC_KEY_GENERATION))
                    .withAnyParameters()
                    .buildForContext(new PublicKeyContext(Map.of("algorithm", "EC")))
                    .inBundle(() -> "PyCrypto")
                    .withoutDependingDetectionRules();

    // EdDSA signature scheme - sign and verify methods (called on the result of .new())
    private static final IDetectionRule<Tree> EDDSA =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("Crypto.Signature.eddsa", "Cryptodome.Signature.eddsa")
                    .forMethods("new")
                    .shouldBeDetectedAs(new ValueActionFactory<>("EDDSA"))
                    .withNamedMethodParameter(
                            "key", ANY) // Crypto.PublicKey.ECCkey or Cryptodome.PublicKey.ECCkey
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .asChildOfParameterWithId(-1)
                    .addDependingDetectionRules(
                            Stream.concat(
                                            RuleSets.rulesOf(PythonCryptoECC.class).stream(),
                                            Stream.of(
                                                    EDDSA_IMPORT_PRIVATE_KEY,
                                                    EDDSA_IMPORT_PUBLIC_KEY))
                                    .toList())
                    .withNamedMethodParameter("mode", "str")
                    .withOptionalNamedMethodParameter("context", ANY)
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> "PyCrypto")
                    .withDependingDetectionRules(List.of(EDDSA_SIGN, EDDSA_VERIFY));

    @Nonnull
    @Override
    protected List<IDetectionRule<Tree>> buildRules() {
        return List.of(
                PKCS1V15, PSS, PSS_MGF1, DSS, DSS_CRYPTODOME, ECDSA, ECDSA_CRYPTODOME, EDDSA);
    }
}
