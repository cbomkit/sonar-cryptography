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

import com.ibm.engine.rule.IDetectionRule;
import com.ibm.plugin.rules.detection.aead.PycaAEAD;
import com.ibm.plugin.rules.detection.aead.PycaAES;
import com.ibm.plugin.rules.detection.asymmetric.PycaDSA;
import com.ibm.plugin.rules.detection.asymmetric.PycaDiffieHellman;
import com.ibm.plugin.rules.detection.asymmetric.PycaEllipticCurve;
import com.ibm.plugin.rules.detection.asymmetric.PycaRSA;
import com.ibm.plugin.rules.detection.asymmetric.PycaSign;
import com.ibm.plugin.rules.detection.fernet.PycaFernet;
import com.ibm.plugin.rules.detection.hash.PycaHash;
import com.ibm.plugin.rules.detection.kdf.PycaKDF;
import com.ibm.plugin.rules.detection.keyagreement.PycaKeyAgreement;
import com.ibm.plugin.rules.detection.mac.PycaMAC;
import com.ibm.plugin.rules.detection.symmetric.PycaCipher;
import com.ibm.plugin.rules.detection.wrapping.PycaWrapping;
import java.util.List;
import java.util.function.Supplier;
import java.util.stream.Stream;
import javax.annotation.Nonnull;
import org.sonar.plugins.python.api.tree.Tree;

public final class PythonDetectionRules {
    private PythonDetectionRules() {
        // private
    }

    private static final Supplier<List<IDetectionRule<Tree>>> RULES =
            Memoize.of(PythonDetectionRules::buildRules);

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return RULES.get();
    }

    @Nonnull
    private static List<IDetectionRule<Tree>> buildRules() {
        return Stream.of(
                        // rules
                        PycaKeyAgreement.rules().stream(),
                        PycaSign.rules().stream(),
                        PycaEllipticCurve.rules().stream(),
                        PycaRSA.rules().stream(),
                        PycaDiffieHellman.rules().stream(),
                        PycaDSA.rules().stream(),
                        PycaAEAD.rules().stream(),
                        PycaAES.rules().stream(),
                        PycaCipher.rules().stream(),
                        PycaHash.wrapperRules().stream(),
                        PycaMAC.rules().stream(),
                        PycaWrapping.rules().stream(),
                        PycaKDF.rules().stream(),
                        PycaFernet.rules().stream())
                .flatMap(i -> i)
                .toList();
    }
}
