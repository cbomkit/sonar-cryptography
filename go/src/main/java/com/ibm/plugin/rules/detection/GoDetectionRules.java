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
import java.util.List;
import java.util.stream.Stream;
import javax.annotation.Nonnull;
import org.sonar.plugins.go.api.Tree;

public final class GoDetectionRules {
    private GoDetectionRules() {
        // private
    }

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return Stream.of(
                        GoCryptoAES.rules().stream(),
                        GoCryptoDES.rules().stream(),
                        GoCryptoDSA.rules().stream(),
                        GoCryptoECDH.rules().stream(),
                        GoCryptoECDSA.rules().stream(),
                        GoCryptoEd25519.rules().stream(),
                        GoCryptoElliptic.rules().stream(),
                        GoCryptoHKDF.rules().stream(),
                        GoCryptoHMAC.rules().stream(),
                        GoCryptoMLKEM.rules().stream(),
                        GoCryptoMD5.rules().stream(),
                        GoCryptoPBKDF2.rules().stream(),
                        GoCryptoRC4.rules().stream(),
                        GoCryptoRSA.rules().stream(),
                        GoCryptoRand.rules().stream(),
                        GoCryptoSHA1.rules().stream(),
                        GoCryptoSHA256.rules().stream(),
                        GoCryptoSHA3.rules().stream(),
                        GoCryptoSHA512.rules().stream())
                .flatMap(i -> i)
                .toList();
    }
}
