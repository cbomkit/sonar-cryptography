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
import com.ibm.plugin.rules.detection.gocrypto.GoCryptoAES;
import com.ibm.plugin.rules.detection.gocrypto.GoCryptoDES;
import com.ibm.plugin.rules.detection.gocrypto.GoCryptoDSA;
import com.ibm.plugin.rules.detection.gocrypto.GoCryptoECDH;
import com.ibm.plugin.rules.detection.gocrypto.GoCryptoECDSA;
import com.ibm.plugin.rules.detection.gocrypto.GoCryptoEd25519;
import com.ibm.plugin.rules.detection.gocrypto.GoCryptoElliptic;
import com.ibm.plugin.rules.detection.gocrypto.GoCryptoHKDF;
import com.ibm.plugin.rules.detection.gocrypto.GoCryptoHMAC;
import com.ibm.plugin.rules.detection.gocrypto.GoCryptoMD5;
import com.ibm.plugin.rules.detection.gocrypto.GoCryptoMLKEM;
import com.ibm.plugin.rules.detection.gocrypto.GoCryptoPBKDF2;
import com.ibm.plugin.rules.detection.gocrypto.GoCryptoRC4;
import com.ibm.plugin.rules.detection.gocrypto.GoCryptoRSA;
import com.ibm.plugin.rules.detection.gocrypto.GoCryptoRand;
import com.ibm.plugin.rules.detection.gocrypto.GoCryptoSHA1;
import com.ibm.plugin.rules.detection.gocrypto.GoCryptoSHA256;
import com.ibm.plugin.rules.detection.gocrypto.GoCryptoSHA3;
import com.ibm.plugin.rules.detection.gocrypto.GoCryptoSHA512;
import com.ibm.plugin.rules.detection.gocrypto.GoCryptoTLS;
import java.util.List;
import java.util.stream.Stream;
import javax.annotation.Nonnull;
import org.sonar.plugins.go.api.Tree;

public final class GoDetectionRules extends DetectionRuleSet<Tree> {

    @Nonnull
    @Override
    protected List<IDetectionRule<Tree>> buildRules() {
        return Stream.of(
                        RuleSets.rulesOf(GoCryptoAES.class).stream(),
                        RuleSets.rulesOf(GoCryptoDES.class).stream(),
                        RuleSets.rulesOf(GoCryptoDSA.class).stream(),
                        RuleSets.rulesOf(GoCryptoECDH.class).stream(),
                        RuleSets.rulesOf(GoCryptoECDSA.class).stream(),
                        RuleSets.rulesOf(GoCryptoEd25519.class).stream(),
                        RuleSets.rulesOf(GoCryptoElliptic.class).stream(),
                        RuleSets.rulesOf(GoCryptoHKDF.class).stream(),
                        RuleSets.rulesOf(GoCryptoHMAC.class).stream(),
                        RuleSets.rulesOf(GoCryptoMLKEM.class).stream(),
                        RuleSets.rulesOf(GoCryptoMD5.class).stream(),
                        RuleSets.rulesOf(GoCryptoPBKDF2.class).stream(),
                        RuleSets.rulesOf(GoCryptoRC4.class).stream(),
                        RuleSets.rulesOf(GoCryptoRSA.class).stream(),
                        RuleSets.rulesOf(GoCryptoRand.class).stream(),
                        RuleSets.rulesOf(GoCryptoSHA1.class).stream(),
                        RuleSets.rulesOf(GoCryptoSHA256.class).stream(),
                        RuleSets.rulesOf(GoCryptoSHA3.class).stream(),
                        RuleSets.rulesOf(GoCryptoSHA512.class).stream(),
                        RuleSets.rulesOf(GoCryptoTLS.class).stream())
                // TODO: GoCryptoX509
                .flatMap(i -> i)
                .toList();
    }
}
