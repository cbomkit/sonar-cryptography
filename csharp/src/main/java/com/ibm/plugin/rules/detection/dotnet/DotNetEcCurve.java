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
package com.ibm.plugin.rules.detection.dotnet;

import com.ibm.engine.detection.MethodMatcher;
import com.ibm.engine.language.csharp.tree.CSharpTree;
import com.ibm.engine.model.context.KeyContext;
import com.ibm.engine.model.factory.CurveFactory;
import com.ibm.engine.rule.DetectionRuleSet;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import java.util.List;
import javax.annotation.Nonnull;

/**
 * The {@code ECCurve} factory methods, as depending rules for an argument position that expects a
 * curve.
 *
 * <p>A curve reaches {@code ECDsa.Create} or {@code ECDiffieHellman.Create} either as a constant
 * member of {@code ECCurve.NamedCurves}, which the rule's own value factory reads, or as a call to
 * one of these factory methods, whose curve lives in the <em>nested</em> call's argument and is
 * therefore not a resolvable value of the outer call at all. The two cases are covered by different
 * mechanisms for that reason, and the engine runs these rules only when the value factory found
 * nothing, so a call site can never yield two competing curves.
 *
 * <p>Shared by {@link DotNetECDsa} and {@link DotNetECDiffieHellman} because both take a curve in
 * exactly the same way.
 */
public final class DotNetEcCurve extends DetectionRuleSet<CSharpTree> {

    // ECCurve.CreateFromFriendlyName("secp256k1") / CreateFromValue(oid) / CreateFromOid(oid)
    private static final IDetectionRule<CSharpTree> EC_CURVE_FROM_NAME =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("ECCurve")
                    .forMethods("CreateFromFriendlyName", "CreateFromValue", "CreateFromOid")
                    .withMethodParameter(MethodMatcher.ANY)
                    .shouldBeDetectedAs(new CurveFactory<>())
                    .buildForContext(new KeyContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    @Nonnull
    @Override
    protected List<IDetectionRule<CSharpTree>> buildRules() {
        return List.of(EC_CURVE_FROM_NAME);
    }
}
