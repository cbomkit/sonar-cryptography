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
package com.ibm.plugin.rules.detection.random;

import static com.ibm.plugin.rules.detection.TypeShortcuts.BYTE_ARRAY_TYPE;

import com.ibm.engine.model.context.PRNGContext;
import com.ibm.engine.model.factory.SeedSizeFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.plugin.rules.detection.Memoize;
import java.util.List;
import java.util.function.Supplier;
import javax.annotation.Nonnull;
import org.sonar.plugins.java.api.tree.Tree;

/**
 *
 *
 * <h1>Secure Random</h1>
 *
 * <p>Links:
 * <li><a href="https://metebalci.com/blog/everything-about-javas-securerandom/">Everything about
 *     Java's SecureRandom</a>
 * <li><a
 *     href="https://stackoverflow.com/questions/27622625/securerandom-with-nativeprng-vs-sha1prng">SecureRandom
 *     with NativePRNG vs SHA1PRNG</a>
 *
 *     <p>
 *
 *     <h3>TL;DR: Use new SecureRandom() when you're not sure and let the system figure it out.
 *     Possibly use SecureRandom.getInstanceStrong() for long term key generation.</h3>
 *
 *     <p>Do not expect a random number generator to generate a specific output sequence within a
 *     runtime application, not even if you seed it yourself. With random number generators it is
 *     always hard to say which is best. Linux and most Unixes have a pretty well thought out random
 *     number generator, so it doesn't hurt to use /dev/random or /dev/urandom, i.e. "NativePRNG".
 *     Problem with using /dev/random is that it blocks until enough entropy is available. So I
 *     would advice against it unless you've got some special requirements with regards to key
 *     generation.
 *
 *     <p>"SHA1PRNG" uses a hash function and a counter, together with a seed. The algorithm is
 *     relatively simple, but it hasn't been described well. It is generally thought of to be
 *     secure. As it only seeds from one of the system generators during startup and therefore
 *     requires fewer calls to the kernel it is likely to be less resource intensive - on my system
 *     it runs about 9 times faster than the "NativePRNG" (which is configured to use /dev/urandom).
 *     Both seem to tax only one core of my dual core Ubuntu laptop (at a time, it frequently
 *     switched from one core to another, that's probably kernel scheduling that's which is to
 *     blame). If you need high performance, choose this one, especially if the /dev/urandom device
 *     is slow on the specific system configuration.
 *
 *     <p>Note that the "SHA1PRNG" present in the retired Apache Harmony implementation is different
 *     from the one in the SUN provider (used by Oracle in the standard Java SE implementation). The
 *     version within Jakarta was used in older versions of Android as well. Although I haven't been
 *     able to do a full review, it doesn't look to be very secure.
 *
 *     <p>EDIT: and I wasn't half wrong about this, SHA1PRNG has been shown not to be pseudo-random
 *     for versions < 4.2.2 and more <a
 *     href="https://blog.k3170makan.com/2013/08/more-details-on-android-jca-prng-flaw.html">here</a>.
 *
 *     <p>Beware that "SHA1PRNG" is not an implementation requirement for Java SE. On most runtimes
 *     it will be present, but directly referencing it from code will make your code less portable.
 *
 *     <p>Nowadays (Java 9 onwards) the OpenJDK and Oracle JDK also contain multiple implementations
 *     that are simply called "DRBG". This implements a list of Dynamic Random Bit Generators
 *     specified by NIST in SP-108. These are not Java implementation requirements either. They
 *     could however be used if a FIPS compliant random number generator is required.
 */
@SuppressWarnings("java:S1192")
public final class SecureRandomGetInstance {

    private static final IDetectionRule<Tree> SECURE_RANDOM_1 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("java.security.SecureRandom")
                    .forConstructor()
                    .withMethodParameter(BYTE_ARRAY_TYPE)
                    .shouldBeDetectedAs(new SeedSizeFactory<>())
                    .buildForContext(new PRNGContext())
                    .inBundle(() -> "Random")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> SECURE_RANDOM_2 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("java.security.SecureRandom")
                    .forMethods("setSeed")
                    .withMethodParameter(BYTE_ARRAY_TYPE)
                    .shouldBeDetectedAs(new SeedSizeFactory<>())
                    .buildForContext(new PRNGContext())
                    .inBundle(() -> "Random")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> SECURE_RANDOM_3 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("java.security.SecureRandom")
                    .forMethods("setSeed")
                    .withMethodParameter("long")
                    .shouldBeDetectedAs(new SeedSizeFactory<>())
                    .buildForContext(new PRNGContext())
                    .inBundle(() -> "Random")
                    .withoutDependingDetectionRules();

    private SecureRandomGetInstance() {
        // nothing
    }

    private static final Supplier<List<IDetectionRule<Tree>>> RULES =
            Memoize.of(SecureRandomGetInstance::buildRules);

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return RULES.get();
    }

    @Nonnull
    private static List<IDetectionRule<Tree>> buildRules() {
        return List.of(SECURE_RANDOM_1, SECURE_RANDOM_2, SECURE_RANDOM_3);
    }
}
