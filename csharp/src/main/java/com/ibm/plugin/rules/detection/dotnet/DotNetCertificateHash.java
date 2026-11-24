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
import com.ibm.engine.model.factory.AlgorithmFactory;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.DetectionRuleSet;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import java.util.List;
import javax.annotation.Nonnull;

/**
 * Detection rules for the certificate thumbprint methods of {@code X509Certificate}.
 *
 * <p>{@code GetCertHash}, {@code GetCertHashString} and {@code TryGetCertHash} take a {@code
 * HashAlgorithmName}. Called without an argument, {@code GetCertHash()} and {@code
 * GetCertHashString()} return the SHA-1 thumbprint.
 *
 * <p>The two rules cannot overlap: the first requires the hash argument, the second matches only a
 * call with no arguments. The digest is the finding itself. An unresolved hash gives no finding.
 */
@SuppressWarnings("java:S1192")
public final class DotNetCertificateHash extends DetectionRuleSet<CSharpTree> {

    // cert.GetCertHash(hashAlgorithm) / cert.GetCertHashString(hashAlgorithm) /
    // cert.TryGetCertHash(hashAlgorithm, destination, out bytesWritten)
    private static final IDetectionRule<CSharpTree> CERT_HASH_WITH_ALGORITHM =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("GetCertHash", "GetCertHashString", "TryGetCertHash")
                    .withNamedMethodParameter("hashAlgorithm", "HashAlgorithmName")
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .withOptionalNamedMethodParameter("destination", MethodMatcher.ANY)
                    .withOptionalNamedMethodParameter("bytesWritten", MethodMatcher.ANY)
                    .buildForContext(new DigestContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // cert.GetCertHash() / cert.GetCertHashString() — the SHA-1 thumbprint
    private static final IDetectionRule<CSharpTree> CERT_HASH_SHA1 =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("GetCertHash", "GetCertHashString")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SHA1"))
                    .withoutParameters()
                    .buildForContext(new DigestContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    @Nonnull
    @Override
    protected List<IDetectionRule<CSharpTree>> buildRules() {
        return List.of(CERT_HASH_WITH_ALGORITHM, CERT_HASH_SHA1);
    }
}
