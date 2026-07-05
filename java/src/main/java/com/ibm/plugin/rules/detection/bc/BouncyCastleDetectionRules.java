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

import com.ibm.engine.rule.IDetectionRule;
import com.ibm.plugin.rules.detection.Memoize;
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
import java.util.function.Supplier;
import java.util.stream.Stream;
import javax.annotation.Nonnull;
import org.sonar.plugins.java.api.tree.Tree;

public final class BouncyCastleDetectionRules {
    private BouncyCastleDetectionRules() {
        // private
    }

    private static final Supplier<List<IDetectionRule<Tree>>> RULES =
            Memoize.of(
                    () ->
                            Stream.of(
                                            // AsymmetricBlockCipher
                                            BcAsymmetricBlockCipher.rules().stream(),
                                            BcBufferedAsymmetricBlockCipher.rules().stream(),
                                            // AEADCipher
                                            BcCCMBlockCipher.rules().stream(),
                                            BcChaCha20Poly1305.rules().stream(),
                                            BcEAXBlockCipher.rules().stream(),
                                            BcGCMBlockCipher.rules().stream(),
                                            BcGCMSIVBlockCipher.rules().stream(),
                                            BcKCCMBlockCipher.rules().stream(),
                                            BcKGCMBlockCipher.rules().stream(),
                                            BcOCBBlockCipher.rules().stream(),
                                            BcAEADCipherEngine.rules().stream(),
                                            // BlockCipher
                                            BcBlockCipher.rules().stream(),
                                            BcBlockCipherEngine.rules().stream(),
                                            // BufferedBlockCipher
                                            BcBufferedBlockCipher.rules().stream(),
                                            // StreamCipher
                                            BcStreamCipherEngine.rules().stream(),
                                            // Digest
                                            BcDigests.rules().stream(),
                                            // Mac
                                            BcMac.rules().stream(),
                                            // PBE
                                            BcPBEParametersGenerator.rules().stream(),
                                            // Wrapper
                                            BcWrapperEngine.rules().stream(),
                                            // BasicAgreement
                                            BcBasicAgreement.rules().stream(),
                                            // DerivationFunction
                                            BcDerivationFunction.rules().stream(),
                                            // EncapsulatedSecret
                                            BcEncapsulatedSecretGenerator.rules().stream(),
                                            BcEncapsulatedSecretExtractor.rules().stream(),
                                            // DSA
                                            BcDSA.rules().stream(),
                                            // Signer
                                            BcSigner.rules().stream(),
                                            // Asymmetric Key Pair Generators
                                            BcAsymmetricCipherKeyPairGenerators.rules().stream(),
                                            // Other
                                            BcIESEngine.rules().stream(),
                                            BcSM2Engine.rules().stream())
                                    .flatMap(i -> i)
                                    .toList());

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return RULES.get();
    }
}
