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
package com.ibm.plugin.rules.detection.bc;

import com.ibm.engine.rule.DetectionRuleSet;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.RuleSets;
import com.ibm.plugin.rules.detection.bc.aeadcipher.BcAEADCipherEngine;
import com.ibm.plugin.rules.detection.bc.aeadcipher.BcCCMBlockCipher;
import com.ibm.plugin.rules.detection.bc.aeadcipher.BcChaCha20Poly1305;
import com.ibm.plugin.rules.detection.bc.aeadcipher.BcEAXBlockCipher;
import com.ibm.plugin.rules.detection.bc.aeadcipher.BcGCMBlockCipher;
import com.ibm.plugin.rules.detection.bc.aeadcipher.BcGCMSIVBlockCipher;
import com.ibm.plugin.rules.detection.bc.aeadcipher.BcKCCMBlockCipher;
import com.ibm.plugin.rules.detection.bc.aeadcipher.BcKGCMBlockCipher;
import com.ibm.plugin.rules.detection.bc.aeadcipher.BcOCBBlockCipher;
import com.ibm.plugin.rules.detection.bc.asymmetricblockcipher.BcAsymmetricBlockCipher;
import com.ibm.plugin.rules.detection.bc.asymmetricblockcipher.BcBufferedAsymmetricBlockCipher;
import com.ibm.plugin.rules.detection.bc.asymmetrickeypair.BcAsymmetricCipherKeyPairGenerators;
import com.ibm.plugin.rules.detection.bc.basicagreement.BcBasicAgreement;
import com.ibm.plugin.rules.detection.bc.blockcipher.BcBlockCipher;
import com.ibm.plugin.rules.detection.bc.blockcipher.BcBlockCipherEngine;
import com.ibm.plugin.rules.detection.bc.bufferedblockcipher.BcBufferedBlockCipher;
import com.ibm.plugin.rules.detection.bc.derivationfunction.BcDerivationFunction;
import com.ibm.plugin.rules.detection.bc.digest.BcDigests;
import com.ibm.plugin.rules.detection.bc.dsa.BcDSA;
import com.ibm.plugin.rules.detection.bc.encapsulatedsecret.BcEncapsulatedSecretExtractor;
import com.ibm.plugin.rules.detection.bc.encapsulatedsecret.BcEncapsulatedSecretGenerator;
import com.ibm.plugin.rules.detection.bc.mac.BcMac;
import com.ibm.plugin.rules.detection.bc.other.BcIESEngine;
import com.ibm.plugin.rules.detection.bc.other.BcSM2Engine;
import com.ibm.plugin.rules.detection.bc.pbe.BcPBEParametersGenerator;
import com.ibm.plugin.rules.detection.bc.signer.BcSigner;
import com.ibm.plugin.rules.detection.bc.streamcipher.BcStreamCipherEngine;
import com.ibm.plugin.rules.detection.bc.wrapper.BcWrapperEngine;
import java.util.List;
import java.util.stream.Stream;
import javax.annotation.Nonnull;
import org.sonar.plugins.java.api.tree.Tree;

public final class BouncyCastleDetectionRules extends DetectionRuleSet<Tree> {

    /** Temporary shim, removed in the call-site cleanup. */
    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return RuleSets.rulesOf(BouncyCastleDetectionRules.class);
    }

    @Nonnull
    @Override
    protected List<IDetectionRule<Tree>> buildRules() {
        return Stream.of(
                        // AsymmetricBlockCipher
                        RuleSets.rulesOf(BcAsymmetricBlockCipher.class).stream(),
                        RuleSets.rulesOf(BcBufferedAsymmetricBlockCipher.class).stream(),
                        // AEADCipher
                        RuleSets.rulesOf(BcCCMBlockCipher.class).stream(),
                        RuleSets.rulesOf(BcChaCha20Poly1305.class).stream(),
                        RuleSets.rulesOf(BcEAXBlockCipher.class).stream(),
                        RuleSets.rulesOf(BcGCMBlockCipher.class).stream(),
                        RuleSets.rulesOf(BcGCMSIVBlockCipher.class).stream(),
                        RuleSets.rulesOf(BcKCCMBlockCipher.class).stream(),
                        RuleSets.rulesOf(BcKGCMBlockCipher.class).stream(),
                        RuleSets.rulesOf(BcOCBBlockCipher.class).stream(),
                        RuleSets.rulesOf(BcAEADCipherEngine.class).stream(),
                        // BlockCipher
                        RuleSets.rulesOf(BcBlockCipher.class).stream(),
                        RuleSets.rulesOf(BcBlockCipherEngine.class).stream(),
                        // BufferedBlockCipher
                        RuleSets.rulesOf(BcBufferedBlockCipher.class).stream(),
                        // StreamCipher
                        RuleSets.rulesOf(BcStreamCipherEngine.class).stream(),
                        // Digest
                        RuleSets.rulesOf(BcDigests.class).stream(),
                        // Mac
                        RuleSets.rulesOf(BcMac.class).stream(),
                        // PBE
                        RuleSets.rulesOf(BcPBEParametersGenerator.class).stream(),
                        // Wrapper
                        RuleSets.rulesOf(BcWrapperEngine.class).stream(),
                        // BasicAgreement
                        RuleSets.rulesOf(BcBasicAgreement.class).stream(),
                        // DerivationFunction
                        RuleSets.rulesOf(BcDerivationFunction.class).stream(),
                        // EncapsulatedSecret
                        RuleSets.rulesOf(BcEncapsulatedSecretGenerator.class).stream(),
                        RuleSets.rulesOf(BcEncapsulatedSecretExtractor.class).stream(),
                        // DSA
                        RuleSets.rulesOf(BcDSA.class).stream(),
                        // Signer
                        RuleSets.rulesOf(BcSigner.class).stream(),
                        // Asymmetric Key Pair Generators
                        RuleSets.rulesOf(BcAsymmetricCipherKeyPairGenerators.class).stream(),
                        // Other
                        RuleSets.rulesOf(BcIESEngine.class).stream(),
                        RuleSets.rulesOf(BcSM2Engine.class).stream())
                .flatMap(i -> i)
                .toList();
    }
}
