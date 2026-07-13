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
package com.ibm.engine.hooks;

import com.ibm.engine.callstack.CallContext;
import com.ibm.engine.callstack.DetachedCall;
import com.ibm.engine.detection.MatchContext;
import com.ibm.engine.detection.MethodMatcher;
import com.ibm.engine.language.ILanguageSupport;
import com.ibm.engine.rule.Parameter;
import javax.annotation.Nonnull;

public record MethodInvocationHookWithReturnResolvement<R, T, S, P>(
        @Nonnull T methodDefinition,
        @Nonnull Parameter<T> parameter,
        @Nonnull MatchContext matchContext)
        implements IMethodInvocationHook<R, T, S, P> {
    @Nonnull
    @Override
    public T hookValue() {
        return this.methodDefinition;
    }

    @Nonnull
    @Override
    public Parameter<T> getParameter() {
        return this.parameter;
    }

    @Override
    public boolean isInvocationOn(
            @Nonnull CallContext<R, T> callContext,
            @Nonnull ILanguageSupport<R, T, S, P> languageSupport) {
        if (callContext instanceof DetachedCall<R, T> detached) {
            final MethodMatcher<T> methodMatcher =
                    languageSupport.createMethodMatcherBasedOn(methodDefinition);
            return methodMatcher != null
                    && methodMatcher.matchKeys(
                            detached.invokedObjectType(),
                            detached.methodName(),
                            detached.parameterTypes());
        }
        final T tree = callContext.tree();
        return tree != null && isInvocationOn(tree, languageSupport);
    }

    @Override
    public boolean isInvocationOn(
            @Nonnull T invocationTree, @Nonnull ILanguageSupport<R, T, S, P> languageSupport) {
        MethodMatcher<T> methodMatcher =
                languageSupport.createMethodMatcherBasedOn(methodDefinition);
        if (methodMatcher == null) {
            return false;
        }
        return methodMatcher.match(invocationTree, languageSupport.translation(), matchContext);
    }
}
