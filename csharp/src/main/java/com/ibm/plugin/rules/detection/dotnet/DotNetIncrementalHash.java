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
package com.ibm.plugin.rules.detection.dotnet;

import com.ibm.engine.detection.MethodMatcher;
import com.ibm.engine.language.csharp.tree.CSharpTree;
import com.ibm.engine.model.context.DigestContext;
import com.ibm.engine.model.context.MacContext;
import com.ibm.engine.model.factory.AlgorithmFactory;
import com.ibm.engine.rule.DetectionRuleSet;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import java.util.List;
import javax.annotation.Nonnull;

/**
 * Detection rules for {@code IncrementalHash} — hashing and HMAC computed over several segments
 * instead of one buffer.
 *
 * <p>Both factories take the algorithm as a {@code HashAlgorithmName}, i.e. a member access such as
 * {@code HashAlgorithmName.SHA256}, which the engine resolves to the member name {@code "SHA256"};
 * {@link AlgorithmFactory} then turns that into the algorithm itself. The two factories differ only
 * in the resulting asset kind, so they are told apart by their detection context rather than by any
 * captured value:
 *
 * <ul>
 *   <li>{@code IncrementalHash.CreateHash(HashAlgorithmName)} → a message digest
 *   <li>{@code IncrementalHash.CreateHMAC(HashAlgorithmName, key)} → an HMAC over that digest
 * </ul>
 *
 * <p>The {@code AppendData}/{@code GetHashAndReset}/{@code GetCurrentHash} members carry no
 * cryptographic information beyond the algorithm already captured here, so they get no rules — the
 * algorithm and its kind are fully determined at the factory call.
 */
public final class DotNetIncrementalHash extends DetectionRuleSet<CSharpTree> {

    // IncrementalHash.CreateHash(HashAlgorithmName hashAlgorithm)
    private static final IDetectionRule<CSharpTree> CREATE_HASH =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("IncrementalHash")
                    .forMethods("CreateHash")
                    .withMethodParameter(MethodMatcher.ANY)
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .buildForContext(new DigestContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // IncrementalHash.CreateHMAC(HashAlgorithmName hashAlgorithm, byte[] key)
    // — also has a ReadOnlySpan<byte> key overload, hence two arities.
    private static final IDetectionRule<CSharpTree> CREATE_HMAC =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("IncrementalHash")
                    .forMethods("CreateHMAC")
                    .withMethodParameter(MethodMatcher.ANY)
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .withMethodParameter(MethodMatcher.ANY) // key
                    .buildForContext(new MacContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    @Nonnull
    @Override
    protected List<IDetectionRule<CSharpTree>> buildRules() {
        return List.of(CREATE_HASH, CREATE_HMAC);
    }
}
