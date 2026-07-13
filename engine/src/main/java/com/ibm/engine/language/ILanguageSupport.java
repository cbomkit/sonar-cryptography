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
package com.ibm.engine.language;

import com.ibm.engine.callstack.CallContextStats;
import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.detection.EnumMatcher;
import com.ibm.engine.detection.IBaseMethodVisitorFactory;
import com.ibm.engine.detection.IDetectionEngine;
import com.ibm.engine.detection.MatchContext;
import com.ibm.engine.detection.MethodMatcher;
import com.ibm.engine.executive.DetectionExecutive;
import com.ibm.engine.rule.IDetectionRule;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

/** Interface for adding language support. */
public interface ILanguageSupport<R, T, S, P> {
    /**
     * Returns an object that can perform translation from language-specific objects to a language
     * agnostic representation.
     *
     * @return an object that can perform translation from one language to a language agnostic
     *     representation.
     */
    @Nonnull
    ILanguageTranslation<T> translation();

    /**
     * Creates a new {@link DetectionExecutive} instance for the specified tree and detection rule.
     *
     * @param tree the tree representing the code to analyze
     * @param detectionRule the detection rule to use
     * @param scanContext the context for the scan, which provides information about the file and
     *     the current state of the analysis
     * @return a new {@link DetectionExecutive} instance
     */
    @Nonnull
    DetectionExecutive<R, T, S, P> createDetectionExecutive(
            @Nonnull T tree,
            @Nonnull IDetectionRule<T> detectionRule,
            @Nonnull IScanContext<R, T> scanContext);

    /**
     * Creates a new {@link IDetectionEngine} instance for the specified detection store.
     *
     * <p>The created engine will be used to detect code matching the detection rule provided by the
     * detection store.
     *
     * @param detectionStore the detection store that contains the detection rule adn will store the
     *     detected values.
     * @return a new {@link IDetectionEngine} instance
     */
    @Nonnull
    IDetectionEngine<T, S> createDetectionEngineInstance(
            @Nonnull DetectionStore<R, T, S, P> detectionStore);

    /**
     * Returns an object that can be used to visit methods and perform analysis.
     *
     * <p>The returned visitor will be used to analyze the methods in the code represented by the
     * specified tree.
     *
     * @return an object that can be used to visit methods and perform analysis
     */
    @Nonnull
    IBaseMethodVisitorFactory<T, S> getBaseMethodVisitorFactory();

    /**
     * Returns the enclosing method for the specified expression.
     *
     * @param expression the expression for which to find the enclosing method
     * @return the enclosing method for the specified expression, or null if there is no such method
     */
    @Nonnull
    Optional<T> getEnclosingMethod(@Nonnull T expression);

    /**
     * Creates a new {@link MethodMatcher} instance based on the specified method definition.
     *
     * <p>The returned matcher will be used to match methods in the code represented by the
     * specified tree against the specified method definition.
     *
     * @param methodDefinition the method definition to use for matching
     * @return a new {@link MethodMatcher} instance
     */
    @Nullable MethodMatcher<T> createMethodMatcherBasedOn(@Nonnull T methodDefinition);

    /**
     * Creates a new {@link EnumMatcher} instance based on the specified enum identifier and match
     * context.
     *
     * <p>The returned matcher will be used to match enum values in the code represented by the
     * specified tree against the specified enum identifier and match context.
     *
     * @param enumIdentifier the enum identifier to use for matching
     * @param matchContext the match context that provides information about the file and the
     *     current state of the analysis
     * @return a new {@link EnumMatcher} instance
     */
    @Nullable EnumMatcher<T> createSimpleEnumMatcherFor(
            @Nonnull T enumIdentifier, @Nonnull MatchContext matchContext);

    /**
     * Whether a recorded call may be stored tree-free (detached) instead of retaining its AST for
     * the whole scan. Detaching lets the file's AST be garbage-collected after analysis.
     *
     * <p>Default: conservative {@code false} (retain the tree, today's behavior). Only languages
     * that can faithfully pre-resolve a call's arguments at record time override this.
     *
     * @param tree the recorded call
     * @return {@code true} if the call can be recorded as a detached, tree-free record
     */
    default boolean isDetachableCall(@Nonnull T tree) {
        return false;
    }

    /**
     * Index of a hook's target parameter within the method definition's parameter list, used to
     * pick the matching pre-resolved argument snapshot when replaying a detached call. Returns
     * {@code -1} if it cannot be determined.
     *
     * @param methodDefinition the hooked method definition
     * @param methodParameter the hook's target parameter identifier
     * @return the zero-based parameter index, or {@code -1}
     */
    default int parameterIndexOf(@Nonnull T methodDefinition, @Nonnull T methodParameter) {
        return -1;
    }

    /**
     * Called when a source file has finished being analyzed. Languages that detach recorded calls
     * use this to drop the just-analyzed file's retained ASTs (its same-file detections have
     * already fired). Default: no-op.
     *
     * @param inputFile the file that finished analysis
     */
    default void notifyLeaveFile(@Nonnull org.sonar.api.batch.fs.InputFile inputFile) {
        // no-op by default
    }

    /**
     * Diagnostics-only: a read-only snapshot of the language's recorded-call population, exposed
     * for the performance/heap harness and scan-floor attribution. This is <em>not</em> part of the
     * detection contract — no detection behaviour depends on it, and languages that do not
     * accumulate a call stack simply return {@link CallContextStats#EMPTY}.
     *
     * @return the current call-context stats; never {@code null}
     */
    @Nonnull
    default CallContextStats callContextStats() {
        return CallContextStats.EMPTY;
    }
}
