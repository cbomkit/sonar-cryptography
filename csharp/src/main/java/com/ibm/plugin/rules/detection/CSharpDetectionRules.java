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

import com.ibm.engine.language.csharp.tree.CSharpTree;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.plugin.rules.detection.dotnet.DotNetAES;
import com.ibm.plugin.rules.detection.dotnet.DotNetDES;
import com.ibm.plugin.rules.detection.dotnet.DotNetDSA;
import com.ibm.plugin.rules.detection.dotnet.DotNetECDiffieHellman;
import com.ibm.plugin.rules.detection.dotnet.DotNetECDsa;
import com.ibm.plugin.rules.detection.dotnet.DotNetHMAC;
import com.ibm.plugin.rules.detection.dotnet.DotNetRC2;
import com.ibm.plugin.rules.detection.dotnet.DotNetRSA;
import com.ibm.plugin.rules.detection.dotnet.DotNetRfc2898DeriveBytes;
import com.ibm.plugin.rules.detection.dotnet.DotNetSHA;
import com.ibm.plugin.rules.detection.dotnet.DotNetTripleDES;
import java.util.List;
import java.util.stream.Stream;
import javax.annotation.Nonnull;

/** Aggregates all C# detection rule lists. */
public final class CSharpDetectionRules {

    private CSharpDetectionRules() {
        // nothing
    }

    @Nonnull
    public static List<IDetectionRule<CSharpTree>> rules() {
        return Stream.of(
                        DotNetAES.rules().stream(),
                        DotNetDES.rules().stream(),
                        DotNetTripleDES.rules().stream(),
                        DotNetRC2.rules().stream(),
                        DotNetRSA.rules().stream(),
                        DotNetECDsa.rules().stream(),
                        DotNetECDiffieHellman.rules().stream(),
                        DotNetDSA.rules().stream(),
                        DotNetSHA.rules().stream(),
                        DotNetHMAC.rules().stream(),
                        DotNetRfc2898DeriveBytes.rules().stream())
                .flatMap(i -> i)
                .toList();
    }
}
