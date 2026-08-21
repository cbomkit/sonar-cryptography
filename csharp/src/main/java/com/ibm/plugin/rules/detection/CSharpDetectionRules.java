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
import com.ibm.engine.rule.DetectionRuleSet;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.RuleSets;
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
public final class CSharpDetectionRules extends DetectionRuleSet<CSharpTree> {

    @Nonnull
    @Override
    protected List<IDetectionRule<CSharpTree>> buildRules() {
        return Stream.of(
                        RuleSets.rulesOf(DotNetAES.class).stream(),
                        RuleSets.rulesOf(DotNetDES.class).stream(),
                        RuleSets.rulesOf(DotNetTripleDES.class).stream(),
                        RuleSets.rulesOf(DotNetRC2.class).stream(),
                        RuleSets.rulesOf(DotNetRSA.class).stream(),
                        RuleSets.rulesOf(DotNetECDsa.class).stream(),
                        RuleSets.rulesOf(DotNetECDiffieHellman.class).stream(),
                        RuleSets.rulesOf(DotNetDSA.class).stream(),
                        RuleSets.rulesOf(DotNetSHA.class).stream(),
                        RuleSets.rulesOf(DotNetHMAC.class).stream(),
                        RuleSets.rulesOf(DotNetRfc2898DeriveBytes.class).stream())
                .flatMap(i -> i)
                .toList();
    }
}
