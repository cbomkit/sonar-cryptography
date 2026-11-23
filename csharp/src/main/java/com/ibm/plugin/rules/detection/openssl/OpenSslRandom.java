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
package com.ibm.plugin.rules.detection.openssl;

import com.ibm.engine.detection.MethodMatcher;
import com.ibm.engine.language.csharp.tree.CSharpTree;
import com.ibm.engine.model.context.PRNGContext;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.DetectionRuleSet;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import java.util.List;
import java.util.Map;
import javax.annotation.Nonnull;

/**
 * OpenSSL's random byte source.
 *
 * <p>{@code RAND_bytes} and {@code RAND_priv_bytes} draw from OpenSSL's own DRBG, not from the
 * operating system's generator directly, and they let the caller select nothing: there is no
 * algorithm argument and no provider name in the call. The finding is therefore a generic {@code
 * DRBG} node typed as a pseudorandom number generator, which follows the precedent set by {@code
 * NATIVEPRNG} for .NET's and Go's platform generators and by {@code DPAPI} for Windows data
 * protection -- an API that performs cryptography without exposing which algorithm.
 *
 * <p>It is deliberately not reported as the concrete construction. OpenSSL's default public DRBG is
 * CTR-DRBG over AES-256, but that is a configuration default: it can be changed at build time, in
 * {@code openssl.cnf}, or at run time with {@code RAND_set_DRBG_type}, so naming it from a {@code
 * RAND_bytes} call site would be a guess about the deployment rather than a reading of the source.
 * {@code RAND_set_DRBG_type} is not read either -- it takes the name as a string, but a CBOM entry
 * for a DRBG the code merely configures, with no call that uses it, says less than the call sites
 * that do.
 *
 * <p>The number of bytes requested is not captured. It is the length of one output, not a key
 * length or a seed length, and {@code SeedSizeFactory} would file it as the latter.
 */
public final class OpenSslRandom extends DetectionRuleSet<CSharpTree> {

    /** Marks a call that draws from OpenSSL's DRBG. */
    public static final String DRBG = "DRBG";

    @Nonnull
    private static PRNGContext context() {
        return new PRNGContext(Map.of(OpenSslDetectionRules.CONTEXT_KEY, "RAND"));
    }

    /**
     * {@code RAND_bytes(buf, num)}, {@code RAND_priv_bytes(buf, num)} and the deprecated {@code
     * RAND_pseudo_bytes(buf, num)}.
     */
    private static final IDetectionRule<CSharpTree> RAND_BYTES =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("RAND_bytes", "RAND_priv_bytes", "RAND_pseudo_bytes")
                    .shouldBeDetectedAs(new ValueActionFactory<>(DRBG))
                    .withMethodParameter(MethodMatcher.ANY) // buf
                    .withMethodParameter(MethodMatcher.ANY) // num
                    .buildForContext(context())
                    .inBundle(() -> "OpenSsl")
                    .withoutDependingDetectionRules();

    /**
     * {@code RAND_bytes_ex(ctx, buf, num, strength)} and {@code RAND_priv_bytes_ex(ctx, buf, num,
     * strength)}.
     *
     * <p>A rule of its own rather than an arity-open one, so that the four-argument form cannot
     * also be claimed by the two-argument rule above.
     */
    private static final IDetectionRule<CSharpTree> RAND_BYTES_EX =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("RAND_bytes_ex", "RAND_priv_bytes_ex")
                    .shouldBeDetectedAs(new ValueActionFactory<>(DRBG))
                    .withMethodParameter(MethodMatcher.ANY) // ctx
                    .withMethodParameter(MethodMatcher.ANY) // buf
                    .withMethodParameter(MethodMatcher.ANY) // num
                    .withMethodParameter(MethodMatcher.ANY) // strength
                    .buildForContext(context())
                    .inBundle(() -> "OpenSsl")
                    .withoutDependingDetectionRules();

    @Nonnull
    @Override
    protected List<IDetectionRule<CSharpTree>> buildRules() {
        return List.of(RAND_BYTES, RAND_BYTES_EX);
    }
}
