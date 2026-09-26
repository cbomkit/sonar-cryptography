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
import com.ibm.plugin.javascript.api.Tree;
import com.ibm.plugin.rules.detection.nodecrypto.NodeCryptoCipher;
import com.ibm.plugin.rules.detection.nodecrypto.NodeCryptoHMAC;
import com.ibm.plugin.rules.detection.nodecrypto.NodeCryptoHash;
import com.ibm.plugin.rules.detection.nodecrypto.NodeCryptoKDF;
import com.ibm.plugin.rules.detection.nodecrypto.NodeCryptoKeyAgreement;
import com.ibm.plugin.rules.detection.nodecrypto.NodeCryptoKeyGen;
import com.ibm.plugin.rules.detection.nodecrypto.NodeCryptoRSA;
import com.ibm.plugin.rules.detection.nodecrypto.NodeCryptoRandom;
import com.ibm.plugin.rules.detection.nodecrypto.NodeCryptoSign;
import com.ibm.plugin.rules.detection.nodecrypto.NodeCryptoTLS;
import java.util.List;
import java.util.function.Supplier;
import java.util.stream.Stream;
import javax.annotation.Nonnull;

/** Aggregates all JavaScript/Node.js cryptography detection rules. */
public final class JavaScriptDetectionRules {

    private JavaScriptDetectionRules() {
        // private
    }

    private static final Supplier<List<IDetectionRule<Tree>>> RULES =
            Memoize.of(JavaScriptDetectionRules::buildRules);

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return RULES.get();
    }

    @Nonnull
    private static List<IDetectionRule<Tree>> buildRules() {
        return Stream.of(
                        NodeCryptoKeyAgreement.rules().stream(),
                        NodeCryptoSign.rules().stream(),
                        NodeCryptoRSA.rules().stream(),
                        NodeCryptoKeyGen.rules().stream(),
                        NodeCryptoCipher.rules().stream(),
                        NodeCryptoHash.rules().stream(),
                        NodeCryptoHMAC.rules().stream(),
                        NodeCryptoKDF.rules().stream(),
                        NodeCryptoRandom.rules().stream(),
                        NodeCryptoTLS.rules().stream())
                .flatMap(i -> i)
                .toList();
    }
}
