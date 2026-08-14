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
import com.ibm.engine.model.context.PrivateKeyContext;
import com.ibm.engine.model.context.PublicKeyContext;
import com.ibm.engine.model.context.SignatureContext;
import com.ibm.engine.model.factory.AlgorithmFactory;
import com.ibm.engine.model.factory.KeyActionFactory;
import com.ibm.engine.model.factory.SignatureActionFactory;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.plugin.rules.detection.Memoize;
import com.ibm.plugin.rules.detection.pycrypto.hash.PythonCryptoHash;
import com.ibm.plugin.rules.detection.pycrypto.publickey.PythonCryptoPublicKey;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import java.util.stream.Stream;
import javax.annotation.Nonnull;
import org.sonar.plugins.python.api.tree.Tree;

@SuppressWarnings("java:S1192")
public final class PythonCryptoSignature {

    private PythonCryptoSignature() {
        // private
    }

    private static final IDetectionRule<Tree> SIGN =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(ANY)
                    .forMethods("sign")
                    .shouldBeDetectedAs(new SignatureActionFactory<>(SignatureAction.Action.SIGN))
                    .withMethodParameter(ANY) // Crypto.Hash.* or Cryptodome.Hash.*
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .asChildOfParameterWithId(-1)
                    .addDependingDetectionRules(PythonCryptoHash.rules())
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> "PyCrypto")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> VERIFY =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(ANY)
                    .forMethods("verify")
                    .shouldBeDetectedAs(new SignatureActionFactory<>(SignatureAction.Action.VERIFY))
                    .withMethodParameter(ANY) // Crypto.Hash.* or Cryptodome.Hash.*
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .asChildOfParameterWithId(-1)
                    .addDependingDetectionRules(PythonCryptoHash.rules())
                    .withMethodParameter(ANY) // the signature to be verified
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
                    .withMethodParameter(ANY) // Crypto.PublicKey.RSA or Cryptodome.PublicKey.RSA
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .asChildOfParameterWithId(-1)
                    .addDependingDetectionRules(PythonCryptoPublicKey.RSARules())
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
                    .withMethodParameter(
                            ANY) // Crypto.PublicKey.RSAkey or Cryptodome.PublicKey.RSAkey
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .asChildOfParameterWithId(-1)
                    .addDependingDetectionRules(PythonCryptoPublicKey.RSARules())
                    .withOtherParameters()
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
                    .withMethodParameter(ANY)
                    .withMethodParameter(ANY)
                    .withMethodParameter(ANY) // Crypto.Hash.* or Cryptodome.Hash.*
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .asChildOfParameterWithId(-1)
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> "PyCrypto")
                    .withDependingDetectionRules(List.of(SIGN, VERIFY));

    // DSS signature scheme - sign and verify methods (called on the result of .new())
    private static final IDetectionRule<Tree> DSS =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("Crypto.Signature.DSS")
                    .forMethods("new")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DSS"))
                    .withMethodParameter("Crypto.PublicKey.DSA") // key
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .asChildOfParameterWithId(-1)
                    .addDependingDetectionRules(PythonCryptoPublicKey.DSARules())
                    .withOtherParameters() // mode, encoding, randfunc
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
                    .withMethodParameter("Cryptodome.PublicKey.DSA") // key
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .asChildOfParameterWithId(-1)
                    .addDependingDetectionRules(PythonCryptoPublicKey.DSARules())
                    .withOtherParameters() // mode, encoding, randfunc
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
                    .withMethodParameter("Crypto.PublicKey.ECC")
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .asChildOfParameterWithId(-1)
                    .addDependingDetectionRules(PythonCryptoPublicKey.ECCRules())
                    .withOtherParameters() // mode, encoding, rand_func
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
                    .withMethodParameter("Cryptodome.PublicKey.ECC")
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .asChildOfParameterWithId(-1)
                    .addDependingDetectionRules(PythonCryptoPublicKey.ECCRules())
                    .withOtherParameters() // mode, encoding, rand_func
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> "PyCrypto")
                    .withDependingDetectionRules(List.of(SIGN, VERIFY));

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
                    .withMethodParameter(
                            ANY) // Crypto.PublicKey.ECCkey or Cryptodome.PublicKey.ECCkey
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .asChildOfParameterWithId(-1)
                    .addDependingDetectionRules(
                            Stream.concat(
                                            PythonCryptoPublicKey.ECCRules().stream(),
                                            Stream.of(
                                                    EDDSA_IMPORT_PRIVATE_KEY,
                                                    EDDSA_IMPORT_PUBLIC_KEY))
                                    .toList())
                    .withOtherParameters() // mode, context
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> "PyCrypto")
                    .withDependingDetectionRules(List.of(SIGN, VERIFY));

    @Nonnull
    private static final Supplier<List<IDetectionRule<Tree>>> RULES =
            Memoize.of(PythonCryptoSignature::buildRules);

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return RULES.get();
    }

    @Nonnull
    private static List<IDetectionRule<Tree>> buildRules() {
        return List.of(
                PKCS1V15, PSS, PSS_MGF1, DSS, DSS_CRYPTODOME, ECDSA, ECDSA_CRYPTODOME, EDDSA);
    }
}
