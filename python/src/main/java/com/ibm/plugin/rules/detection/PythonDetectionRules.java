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
package com.ibm.plugin.rules.detection;

import com.ibm.engine.rule.DetectionRuleSet;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.RuleSets;
import com.ibm.plugin.rules.detection.pyca.aead.PycaAEAD;
import com.ibm.plugin.rules.detection.pyca.aead.PycaAES;
import com.ibm.plugin.rules.detection.pyca.asymmetric.PycaDSA;
import com.ibm.plugin.rules.detection.pyca.asymmetric.PycaDiffieHellman;
import com.ibm.plugin.rules.detection.pyca.asymmetric.PycaEllipticCurve;
import com.ibm.plugin.rules.detection.pyca.asymmetric.PycaRSA;
import com.ibm.plugin.rules.detection.pyca.asymmetric.PycaSign;
import com.ibm.plugin.rules.detection.pyca.fernet.PycaFernet;
import com.ibm.plugin.rules.detection.pyca.hash.PycaHashWrapper;
import com.ibm.plugin.rules.detection.pyca.kdf.PycaKDF;
import com.ibm.plugin.rules.detection.pyca.keyagreement.PycaKeyAgreement;
import com.ibm.plugin.rules.detection.pyca.mac.PycaMAC;
import com.ibm.plugin.rules.detection.pyca.symmetric.PycaCipher;
import com.ibm.plugin.rules.detection.pyca.wrapping.PycaWrapping;
import com.ibm.plugin.rules.detection.pycrypto.cipher.PythonCryptoCipher;
import com.ibm.plugin.rules.detection.pycrypto.hash.PythonCryptoHash;
import com.ibm.plugin.rules.detection.pycrypto.kdf.PythonCryptoKDF;
import com.ibm.plugin.rules.detection.pycrypto.keyagreement.PythonCryptoKeyAgreement;
import com.ibm.plugin.rules.detection.pycrypto.mac.PythonCryptoMac;
import com.ibm.plugin.rules.detection.pycrypto.publickey.PythonCryptoElGamal;
import com.ibm.plugin.rules.detection.pycrypto.random.PythonCryptoRandom;
import com.ibm.plugin.rules.detection.pycrypto.signature.PythonCryptoSignature;
import java.util.List;
import java.util.stream.Stream;
import javax.annotation.Nonnull;
import org.sonar.plugins.python.api.tree.Tree;

public final class PythonDetectionRules extends DetectionRuleSet<Tree> {

    @Nonnull
    @Override
    protected List<IDetectionRule<Tree>> buildRules() {
        return Stream.of(
                        // rules
                        RuleSets.rulesOf(PycaKeyAgreement.class).stream(),
                        RuleSets.rulesOf(PycaSign.class).stream(),
                        RuleSets.rulesOf(PycaEllipticCurve.class).stream(),
                        RuleSets.rulesOf(PycaRSA.class).stream(),
                        RuleSets.rulesOf(PycaDiffieHellman.class).stream(),
                        RuleSets.rulesOf(PycaDSA.class).stream(),
                        RuleSets.rulesOf(PycaAEAD.class).stream(),
                        RuleSets.rulesOf(PycaAES.class).stream(),
                        RuleSets.rulesOf(PycaCipher.class).stream(),
                        RuleSets.rulesOf(PycaHashWrapper.class).stream(),
                        RuleSets.rulesOf(PycaMAC.class).stream(),
                        RuleSets.rulesOf(PycaWrapping.class).stream(),
                        RuleSets.rulesOf(PycaKDF.class).stream(),
                        RuleSets.rulesOf(PycaFernet.class).stream(),
                        RuleSets.rulesOf(PythonCryptoHash.class).stream(),
                        RuleSets.rulesOf(PythonCryptoMac.class).stream(),
                        RuleSets.rulesOf(PythonCryptoRandom.class).stream(),
                        RuleSets.rulesOf(PythonCryptoCipher.class).stream(),
                        RuleSets.rulesOf(PythonCryptoElGamal.class).stream(),
                        RuleSets.rulesOf(PythonCryptoSignature.class).stream(),
                        RuleSets.rulesOf(PythonCryptoKDF.class).stream(),
                        RuleSets.rulesOf(PythonCryptoKeyAgreement.class).stream())
                .flatMap(i -> i)
                .toList();
    }
}
