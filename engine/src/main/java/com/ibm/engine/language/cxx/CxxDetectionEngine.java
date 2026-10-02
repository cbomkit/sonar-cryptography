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
package com.ibm.engine.language.cxx;

import com.ibm.engine.callstack.ArgSnapshot;
import com.ibm.engine.callstack.DetachedCall;
import com.ibm.engine.callstack.DetachedScanContext;
import com.ibm.engine.callstack.RetainedCall;
import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.detection.DetectionStoreWithHook;
import com.ibm.engine.detection.Handler;
import com.ibm.engine.detection.IDetectionEngine;
import com.ibm.engine.detection.IType;
import com.ibm.engine.detection.MatchContext;
import com.ibm.engine.detection.MethodDetection;
import com.ibm.engine.detection.ResolvedValue;
import com.ibm.engine.detection.TraceSymbol;
import com.ibm.engine.detection.ValueDetection;
import com.ibm.engine.hooks.MethodInvocationHookWithParameterResolvement;
import com.ibm.engine.hooks.MethodInvocationHookWithReturnResolvement;
import com.ibm.engine.language.ILanguageTranslation;
import com.ibm.engine.language.IScanContext;
import com.ibm.engine.model.factory.IValueFactory;
import com.ibm.engine.rule.DetectableParameter;
import com.ibm.engine.rule.DetectionRule;
import com.ibm.engine.rule.MethodDetectionRule;
import com.ibm.engine.rule.Parameter;
import com.sonar.cxx.sslr.api.AstNode;
import com.sonar.cxx.sslr.api.GenericTokenType;
import com.sonar.cxx.sslr.api.Grammar;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.sonar.cxx.parser.CxxGrammarImpl;
import org.sonar.cxx.squidbridge.SquidAstVisitorContext;
import org.sonar.cxx.squidbridge.api.AstNodeSymbolExtension;
import org.sonar.cxx.squidbridge.api.SourceCode;
import org.sonar.cxx.squidbridge.api.SourceFile;
import org.sonar.cxx.squidbridge.api.Symbol;
import org.sonar.cxx.squidbridge.checks.SquidCheck;
import org.sonar.cxx.utils.CxxAstNodeHelper;

public class CxxDetectionEngine implements IDetectionEngine<AstNode, Symbol> {
    @Nonnull
    private final DetectionStore<
                    SquidCheck<?>, AstNode, Symbol, SquidAstVisitorContext<? extends Grammar>>
            detectionStore;

    @Nonnull
    private final Handler<SquidCheck<?>, AstNode, Symbol, SquidAstVisitorContext<? extends Grammar>>
            handler;

    public CxxDetectionEngine(
            @Nonnull
                    DetectionStore<
                                    SquidCheck<?>,
                                    AstNode,
                                    Symbol,
                                    SquidAstVisitorContext<? extends Grammar>>
                            detectionStore,
            @Nonnull
                    Handler<
                                    SquidCheck<?>,
                                    AstNode,
                                    Symbol,
                                    SquidAstVisitorContext<? extends Grammar>>
                            handler) {
        this.detectionStore = detectionStore;
        this.handler = handler;
    }

    @Override
    public void run(@Nonnull AstNode tree) {
        run(TraceSymbol.createStart(), tree);
    }

    @Override
    public void run(@Nonnull TraceSymbol<Symbol> traceSymbol, @Nonnull AstNode tree) {
        if (CxxAstNodeHelper.isFunctionCall(tree)) {
            recordCall(tree);
            if (detectionStore
                    .getDetectionRule()
                    .match(tree, handler.getLanguageSupport().translation())) {
                this.analyseExpression(traceSymbol, tree);
            }
        } else if (CxxAstNodeHelper.isConstructorCall(tree)) {
            if (detectionStore
                    .getDetectionRule()
                    .match(tree, handler.getLanguageSupport().translation())) {
                this.analyseExpression(traceSymbol, tree);
            }
        } else if (tree.is(CxxGrammarImpl.enumSpecifier)) {
            handler.addCallToCallStack(tree, detectionStore.getScanContext());
        }
    }

    /**
     * Records a function call for later cross-file hook matching, detaching it from the AST when
     * possible (its arguments are pre-resolved here while the file is live). Falls back to
     * retaining the tree when the call is not detachable or an argument cannot be faithfully
     * snapshotted.
     *
     * <p>{@code run} is invoked once per detection rule for the same call node, so this same {@code
     * invocation} reaches here once per rule too; only the first such call actually needs
     * recording, so every later one exits before doing the argument-resolution and detached-call
     * construction work below.
     */
    private void recordCall(@Nonnull AstNode invocation) {
        if (handler.isCallAlreadyRecorded(invocation)) {
            return;
        }
        final IScanContext<SquidCheck<?>, AstNode> scanContext = detectionStore.getScanContext();
        DetachedCall<SquidCheck<?>, AstNode> detachedForm = null;
        if (handler.getLanguageSupport().isDetachableCall(invocation)) {
            detachedForm = buildDetachedCall(invocation, scanContext);
        }
        handler.addRecordedCall(new RetainedCall<>(invocation, scanContext, detachedForm));
    }

    @Nullable private DetachedCall<SquidCheck<?>, AstNode> buildDetachedCall(
            @Nonnull AstNode invocation,
            @Nonnull IScanContext<SquidCheck<?>, AstNode> scanContext) {
        // A detached call is only ever matched in hook context (MethodMatcher.matchKeys), so its
        // type keys must be snapshotted with hook-context semantics (exact type matching) to
        // reproduce the live retained-call path, which matches via the hook's isHookContext=true
        // MatchContext. Using record-context (isHookContext=false) here would make cross-file
        // matching subtype-permissive and diverge from the same-file result.
        final MatchContext matchContext = MatchContext.createForHookContext();
        final ILanguageTranslation<AstNode> translation =
                handler.getLanguageSupport().translation();
        final Optional<IType> invokedType =
                translation.getInvokedObjectTypeString(matchContext, invocation);
        final Optional<String> name = translation.getMethodName(matchContext, invocation);
        if (invokedType.isEmpty() || name.isEmpty()) {
            return null;
        }
        final List<IType> parameterTypes =
                translation.getMethodParameterTypes(matchContext, invocation);

        final List<ArgSnapshot<AstNode>> arguments = new ArrayList<>();
        final List<AstNode> actualArguments = CxxAstNodeHelper.getFunctionCallArguments(invocation);
        for (int i = 0; i < actualArguments.size(); i++) {
            final List<ResolvedValue<Object, AstNode>> resolved =
                    resolveValuesInInnerScope(Object.class, actualArguments.get(i), null);
            final List<ArgSnapshot.ResolvedSnapshotValue<AstNode>> snapshots = new ArrayList<>();
            for (ResolvedValue<Object, AstNode> resolvedValue : resolved) {
                final CxxDetachedAstNode location =
                        captureLocation(resolvedValue.tree(), resolvedValue.value().toString());
                if (location == null) {
                    return null; // cannot faithfully snapshot -> fall back to retaining the tree
                }
                snapshots.add(
                        new ArgSnapshot.ResolvedSnapshotValue<>(resolvedValue.value(), location));
            }
            arguments.add(new ArgSnapshot<>(i, snapshots));
        }

        final SourceFile sourceFile =
                scanContext instanceof CxxScanContext cxxScanContext
                        ? sourceFileOf(cxxScanContext)
                        : null;
        final CxxDetachedIssueReporter issueReporter =
                sourceFile != null
                        ? CxxDetachedIssueReporter.create(sourceFile, scanContext.getFilePath())
                        : null;
        final DetachedScanContext<SquidCheck<?>, AstNode> detachedScanContext =
                new DetachedScanContext<>(
                        scanContext.getInputFile(), scanContext.getFilePath(), issueReporter);
        return new DetachedCall<>(
                invokedType.get(), name.get(), parameterTypes, arguments, detachedScanContext);
    }

    /**
     * The current file's {@code SourceFile}, captured while the file is live so a detached call's
     * issue reporter can append to it later regardless of which file is being visited when a
     * cross-file hook fires. {@code SourceFile} objects are kept alive for the whole batch by
     * sonar-cxx's own index — see {@link CxxDetachedIssueReporter}.
     */
    @Nullable private SourceFile sourceFileOf(@Nonnull CxxScanContext cxxScanContext) {
        final SourceCode current = cxxScanContext.cxxVisitorContext().peekSourceCode();
        if (current instanceof SourceFile sourceFile) {
            return sourceFile;
        }
        return current == null ? null : current.getParent(SourceFile.class);
    }

    /**
     * Captures a value's location as an AST-free {@link CxxDetachedAstNode}, mirroring {@code
     * CxxTranslator.getDetectionContextFrom} so a detached detection's CBOM occurrence is identical
     * to a non-detached one.
     */
    @Nullable private CxxDetachedAstNode captureLocation(@Nonnull AstNode location, @Nonnull String text) {
        final com.sonar.cxx.sslr.api.Token token = location.getToken();
        if (token == null) {
            return null;
        }
        final List<String> keywords;
        if (CxxAstNodeHelper.isFunctionCall(location)) {
            final String functionName = CxxAstNodeHelper.getFunctionCallName(location);
            keywords = functionName != null ? List.of(functionName) : List.of();
        } else {
            keywords = List.of();
        }
        return new CxxDetachedAstNode(token.getLine(), token.getColumn(), text, keywords);
    }

    @Nullable @Override
    public AstNode extractArgumentFromMethodCaller(
            @Nonnull AstNode methodDefinition,
            @Nonnull AstNode methodInvocation,
            @Nonnull AstNode methodParameterIdentifier) {
        if (!methodDefinition.is(CxxGrammarImpl.functionDefinition)) {
            return null;
        }

        List<AstNode> defParams =
                CxxAstNodeHelper.getFunctionDefinitionParameters(methodDefinition);
        List<AstNode> callArgs;

        if (CxxAstNodeHelper.isFunctionCall(methodInvocation)) {
            callArgs = CxxAstNodeHelper.getFunctionCallArguments(methodInvocation);
        } else if (CxxAstNodeHelper.isConstructorCall(methodInvocation)) {
            AstNode newInitializer = methodInvocation.getFirstChild(CxxGrammarImpl.newInitializer);
            if (newInitializer != null) {
                AstNode expressionList =
                        newInitializer.getFirstDescendant(CxxGrammarImpl.expressionList);
                callArgs = flattenConstructorArgs(expressionList);
            } else {
                callArgs = Collections.emptyList();
            }
        } else {
            return null;
        }

        if (defParams.size() != callArgs.size()) {
            return null;
        }

        final MatchContext matchContext =
                MatchContext.build(false, detectionStore.getDetectionRule());
        Optional<String> targetVarIdOptional =
                handler.getLanguageSupport()
                        .translation()
                        .resolveIdentifierAsString(matchContext, methodParameterIdentifier);

        if (targetVarIdOptional.isEmpty()) {
            return null;
        }
        final String targetVarId = targetVarIdOptional.get();

        for (int i = 0; i < defParams.size(); i++) {
            AstNode paramDecl = defParams.get(i);
            String paramName = CxxAstNodeHelper.getIdentifierName(paramDecl);
            if (paramName != null && paramName.equals(targetVarId)) {
                return callArgs.get(i);
            }
        }
        return null;
    }

    @Nonnull
    @Override
    public <O> List<ResolvedValue<O, AstNode>> resolveValuesInInnerScope(
            @Nonnull Class<O> clazz,
            @Nonnull AstNode expression,
            @Nullable IValueFactory<AstNode> valueFactory) {
        return CxxSemantic.resolveValues(
                clazz, expression, new LinkedList<>(), valueFactory, false, this);
    }

    @Override
    public void resolveValuesInOuterScope(
            @Nonnull AstNode expression, @Nonnull Parameter<AstNode> parameter) {
        Optional<AstNode> optionalMethodNode =
                handler.getLanguageSupport().getEnclosingMethod(expression);
        if (optionalMethodNode.isEmpty()) {
            return;
        }
        AstNode methodNode = optionalMethodNode.get();

        List<ResolvedValue<Object, AstNode>> resolvedValues =
                CxxSemantic.resolveValues(
                        Object.class, expression, new LinkedList<>(), null, true, this);

        if (resolvedValues.size() != 1) {
            return;
        }
        final AstNode resolvedParameter = resolvedValues.get(0).tree();

        createAMethodHook(methodNode, resolvedParameter, parameter);
    }

    private void createAMethodHook(
            @Nonnull AstNode methodNode,
            @Nullable AstNode methodParameter,
            @Nonnull Parameter<AstNode> detectableParameter) {
        final MatchContext matchContext =
                MatchContext.build(true, detectionStore.getDetectionRule());

        if (methodParameter == null) {
            MethodInvocationHookWithReturnResolvement<
                            SquidCheck<?>,
                            AstNode,
                            Symbol,
                            SquidAstVisitorContext<? extends Grammar>>
                    methodInvocationHookWithReturnResolvement =
                            new MethodInvocationHookWithReturnResolvement<>(
                                    methodNode, detectableParameter, matchContext);
            if (this.detectionStore
                    instanceof
                    final DetectionStoreWithHook<
                                    SquidCheck<?>,
                                    AstNode,
                                    Symbol,
                                    SquidAstVisitorContext<? extends Grammar>>
                            detectionStoreWithHook) {
                detectionStoreWithHook.onSuccessiveHook(methodInvocationHookWithReturnResolvement);
            } else {
                handler.addHookToHookRepository(methodInvocationHookWithReturnResolvement);
                detectionStore.onNewHookRegistration(methodInvocationHookWithReturnResolvement);
            }
            return;
        }

        MethodInvocationHookWithParameterResolvement<
                        SquidCheck<?>, AstNode, Symbol, SquidAstVisitorContext<? extends Grammar>>
                methodInvocationHookWithParameterResolvement =
                        new MethodInvocationHookWithParameterResolvement<>(
                                methodNode, methodParameter, detectableParameter, matchContext);
        if (this.detectionStore
                instanceof
                final DetectionStoreWithHook<
                                SquidCheck<?>,
                                AstNode,
                                Symbol,
                                SquidAstVisitorContext<? extends Grammar>>
                        detectionStoreWithHook) {
            detectionStoreWithHook.onSuccessiveHook(methodInvocationHookWithParameterResolvement);
        } else {
            handler.addHookToHookRepository(methodInvocationHookWithParameterResolvement);
            detectionStore.onNewHookRegistration(methodInvocationHookWithParameterResolvement);
        }
    }

    @Override
    public <O> void resolveMethodReturnValues(
            @Nonnull Class<O> clazz,
            @Nonnull AstNode methodDefinition,
            @Nonnull Parameter<AstNode> parameter) {
        if (!methodDefinition.is(CxxGrammarImpl.functionDefinition)) {
            return;
        }
        AstNode body = CxxAstNodeHelper.getFunctionDefinitionBody(methodDefinition);
        if (body == null) {
            return;
        }
        for (AstNode node : body.getDescendants(CxxGrammarImpl.jumpStatement)) {
            if (!CxxAstNodeHelper.isReturnStatement(node)) {
                continue;
            }
            AstNode returnExpr = CxxAstNodeHelper.getReturnExpression(node);
            if (returnExpr == null) {
                continue;
            }
            if (parameter.is(DetectableParameter.class)) {
                DetectableParameter<AstNode> detectable = (DetectableParameter<AstNode>) parameter;
                List<ResolvedValue<O, AstNode>> resolved =
                        resolveValuesInInnerScope(clazz, returnExpr, detectable.getiValueFactory());
                if (!resolved.isEmpty()) {
                    resolved.stream()
                            .map(rv -> new ValueDetection<>(rv, detectable, returnExpr, returnExpr))
                            .forEach(detectionStore::onReceivingNewDetection);
                    continue;
                }
            }
            resolveValuesInOuterScope(returnExpr, parameter);
        }
    }

    @Nullable @Override
    public <O> ResolvedValue<O, AstNode> resolveEnumValue(
            @Nonnull Class<O> clazz,
            @Nonnull AstNode enumClassDefinition,
            @Nonnull LinkedList<AstNode> selections) {
        // CxxSemantic.resolveIdentifier resolves enum constants eagerly during traversal, unlike
        // Java's lazy EnumHook, so no enum reference ever reaches this fallback unresolved.
        return null;
    }

    @Nonnull
    @Override
    public Optional<TraceSymbol<Symbol>> getAssignedSymbol(@Nonnull AstNode expression) {
        Symbol symbol = CxxAstNodeHelper.getAssignedSymbol(expression);
        if (symbol == null && CxxAstNodeHelper.isFunctionCall(expression)) {
            symbol = outputArgumentSymbol(expression);
        }
        if (symbol != null) {
            return Optional.of(TraceSymbol.createFrom(symbol));
        }
        if (CxxAstNodeHelper.isFunctionCall(expression)
                && !CxxAstNodeHelper.isCallOnCallResult(expression)
                && !CxxAstNodeHelper.isMemberAccess(expression)) {
            // the result of a call that is not assigned is used by the call it is an argument
            // of, if any; a returned or discarded result is used by no call of this function
            return Optional.of(
                    isCallArgument(expression)
                            ? TraceSymbol.createWithStateNoSymbol(expression)
                            : TraceSymbol.createWithStateDifferent());
        }
        return Optional.empty();
    }

    /** Whether a call is written as an argument of another call. */
    private static boolean isCallArgument(@Nonnull AstNode call) {
        for (AstNode node = call.getParent(); node != null; node = node.getParent()) {
            if (node.is(CxxGrammarImpl.expressionList)) {
                return CxxAstNodeHelper.isFunctionCall(node.getParent());
            }
            if (node.is(CxxGrammarImpl.statement)
                    || node.is(CxxGrammarImpl.expressionStatement)
                    || node.is(CxxGrammarImpl.jumpStatement)
                    || node.is(CxxGrammarImpl.initDeclarator)) {
                return false;
            }
        }
        return false;
    }

    /** Whether one of the arguments of a call is the traced origin call. */
    private boolean takesOrigin(
            @Nonnull AstNode methodInvocation, @Nonnull TraceSymbol<Symbol> traceSymbol) {
        final Object origin = traceSymbol.getOrigin().orElse(null);
        if (!(origin instanceof AstNode originCall)
                || !CxxAstNodeHelper.isFunctionCall(methodInvocation)) {
            return false;
        }
        for (AstNode argument : CxxAstNodeHelper.getFunctionCallArguments(methodInvocation)) {
            if (argument.getToken() == originCall.getToken()
                    && argument.getLastToken() == originCall.getLastToken()) {
                return true;
            }
        }
        return false;
    }

    /**
     * A C function returns an object through an output argument, the address of a variable, e.g.
     * {@code EVP_PKEY_keygen(ctx, &pkey)}. The variable is the result of a call that is not
     * assigned and has exactly one such argument.
     */
    @Nullable private Symbol outputArgumentSymbol(@Nonnull AstNode functionCall) {
        Symbol output = null;
        for (AstNode argument : CxxAstNodeHelper.getFunctionCallArguments(functionCall)) {
            final Symbol addressed = addressedVariable(argument);
            if (addressed != null) {
                if (output != null) {
                    return null;
                }
                output = addressed;
            }
        }
        return output;
    }

    /** The variable {@code v} of an argument {@code &v}, or null for any other argument. */
    @Nullable private static Symbol addressedVariable(@Nonnull AstNode argument) {
        if (!"&".equals(argument.getTokenValue()) || argument.getNumberOfChildren() != 2) {
            return null;
        }
        return handleSymbol(argument.getLastChild());
    }

    @Nonnull
    @Override
    public Optional<TraceSymbol<Symbol>> getMethodInvocationParameterSymbol(
            @Nonnull AstNode methodInvocation, @Nonnull Parameter<AstNode> parameter) {
        if (CxxAstNodeHelper.isFunctionCall(methodInvocation)) {
            List<AstNode> arguments = CxxAstNodeHelper.getFunctionCallArguments(methodInvocation);
            return getTraceSymbol(parameter, arguments);
        }
        return Optional.empty();
    }

    @Nonnull
    @Override
    public Optional<TraceSymbol<Symbol>> getNewClassParameterSymbol(
            @Nonnull AstNode newClass, @Nonnull Parameter<AstNode> parameter) {
        if (CxxAstNodeHelper.isConstructorCall(newClass)) {
            AstNode newInitializer = newClass.getFirstChild(CxxGrammarImpl.newInitializer);
            if (newInitializer != null) {
                AstNode expressionList =
                        newInitializer.getFirstDescendant(CxxGrammarImpl.expressionList);
                return getTraceSymbol(parameter, flattenConstructorArgs(expressionList));
            }
        }
        return Optional.empty();
    }

    @Nonnull
    private Optional<TraceSymbol<Symbol>> getTraceSymbol(
            @Nonnull Parameter<AstNode> parameter, @Nonnull List<AstNode> arguments) {
        if (parameter.getIndex() >= arguments.size()) {
            return Optional.of(TraceSymbol.createWithStateDifferent());
        }
        AstNode arg = arguments.get(parameter.getIndex());
        Symbol symbol = AstNodeSymbolExtension.getSymbol(arg);
        if (symbol != null && !symbol.isUnknown()) {
            return Optional.of(TraceSymbol.createFrom(symbol));
        }
        // `&v` passes the object v, e.g. the key of AES_cbc_encrypt(in, out, len, &key, iv, enc),
        // so the argument is followed to v, as the call that sets up v assigns it
        final Symbol addressed = addressedVariable(arg);
        if (addressed != null && !addressed.isUnknown()) {
            return Optional.of(TraceSymbol.createFrom(addressed));
        }
        // NO_SYMBOL means "the argument is itself an inline constructing call with no variable to
        // trace" (e.g. foo(new Test())), which triggers a re-scan of the enclosing method for a
        // matching unassigned call. A bare literal/macro argument (e.g. foo(NULL)) is neither a
        // symbol nor a call, so it must map to DIFFERENT instead - otherwise the re-scan would
        // match any unassigned call in the method, not just ones related to this argument.
        if (CxxAstNodeHelper.isFunctionCall(arg) || CxxAstNodeHelper.isConstructorCall(arg)) {
            return Optional.of(TraceSymbol.createWithStateNoSymbol());
        }
        return Optional.of(TraceSymbol.createWithStateDifferent());
    }

    @Override
    public boolean isInvocationOnVariable(
            @Nonnull AstNode methodInvocation, @Nonnull TraceSymbol<Symbol> variableSymbol) {
        if (!CxxAstNodeHelper.isFunctionCall(methodInvocation)) {
            return false;
        }
        if (!variableSymbol.is(TraceSymbol.State.SYMBOL)) {
            return false;
        }
        Symbol variable = variableSymbol.getSymbol();
        if (variable == null) {
            return false;
        }
        return CxxAstNodeHelper.isInvocationOnVariable(methodInvocation, variable, true)
                || isInvocationOnHandle(methodInvocation, variable);
    }

    /**
     * C APIs operate on an object through a handle passed as an argument of a free function, e.g.
     * {@code EVP_KDF_CTX_set_params(kctx, params)} operates on {@code kctx} and {@code
     * EVP_DigestSignInit(mdctx, NULL, md, NULL, pkey)} signs with {@code pkey}. Such a call counts
     * as an invocation on the variable when one of its arguments is exactly that variable, or its
     * address: {@code EVP_SealInit(ctx, type, &ek, &ekl, iv, &pkey, 1)} encrypts with {@code pkey},
     * passed as an array of one key. The calls are those a depending rule names, which operate on
     * the object they are given.
     */
    private boolean isInvocationOnHandle(
            @Nonnull AstNode methodInvocation, @Nonnull Symbol variable) {
        if (CxxAstNodeHelper.isMemberAccess(methodInvocation)) {
            return false;
        }
        for (AstNode argument : CxxAstNodeHelper.getFunctionCallArguments(methodInvocation)) {
            if (handleSymbol(argument) == variable || addressedVariable(argument) == variable) {
                return true;
            }
        }
        return false;
    }

    /** The variable an argument is exactly, or null for any other expression. */
    @Nullable private static Symbol handleSymbol(@Nonnull AstNode argument) {
        if (argument.getToken() != argument.getLastToken()) {
            // an expression such as `&ctx` or `ctx->field` is not the handle itself
            return null;
        }
        Symbol symbol = AstNodeSymbolExtension.getSymbol(argument);
        if (symbol == null) {
            AstNode identifier = argument.getFirstDescendant(GenericTokenType.IDENTIFIER);
            symbol = identifier != null ? AstNodeSymbolExtension.getSymbol(identifier) : null;
        }
        return symbol;
    }

    @Override
    public boolean isInitForVariable(
            @Nonnull AstNode newClass, @Nonnull TraceSymbol<Symbol> variableSymbol) {
        if (!variableSymbol.is(TraceSymbol.State.SYMBOL)) {
            return false;
        }
        Symbol variable = variableSymbol.getSymbol();
        Optional<TraceSymbol<Symbol>> symbolOptional = getAssignedSymbol(newClass);
        if (symbolOptional.isEmpty()) {
            return false;
        }
        TraceSymbol<Symbol> traceSymbol = symbolOptional.get();
        Symbol symbol = traceSymbol.getSymbol();
        if (symbol == null || variable == null) {
            return false;
        }
        return symbol.name().equals(variable.name());
    }

    private void analyseExpression(
            @Nonnull TraceSymbol<Symbol> traceSymbol, @Nonnull AstNode expressionNode) {
        if (detectionStore.getDetectionRule().is(MethodDetectionRule.class)) {
            // like a rule's own action below, the call is a finding of a constrained re-scan only
            // when it is connected to the traced argument
            if (traceSymbol.is(TraceSymbol.State.SYMBOL_IGNORED)
                    || (traceSymbol.is(TraceSymbol.State.NO_SYMBOL)
                            && traceSymbol.getOrigin().isEmpty())
                    || takesOrigin(expressionNode, traceSymbol)
                    || isInvocationOnVariable(expressionNode, traceSymbol)
                    || isInitForVariable(expressionNode, traceSymbol)) {
                MethodDetection<AstNode> methodDetection =
                        new MethodDetection<>(expressionNode, null);
                detectionStore.onReceivingNewDetection(methodDetection);
            }
            return;
        }

        DetectionRule<AstNode> detectionRule =
                (DetectionRule<AstNode>) detectionStore.getDetectionRule();

        List<AstNode> arguments;
        if (CxxAstNodeHelper.isFunctionCall(expressionNode)) {
            arguments = CxxAstNodeHelper.getFunctionCallArguments(expressionNode);
        } else if (CxxAstNodeHelper.isConstructorCall(expressionNode)) {
            AstNode newInitializer = expressionNode.getFirstChild(CxxGrammarImpl.newInitializer);
            if (newInitializer != null) {
                AstNode expressionList =
                        newInitializer.getFirstDescendant(CxxGrammarImpl.expressionList);
                arguments = flattenConstructorArgs(expressionList);
            } else {
                arguments = Collections.emptyList();
            }
        } else {
            return;
        }

        // A chained/builder-pattern call (foo().goo()) has no variable to trace back to - its
        // qualifier is itself a call - so it must not be rejected by the NO_SYMBOL branch in
        // checkCurrentIndexState the way an unrelated assigned call would be.
        boolean isBuilderPattern = CxxAstNodeHelper.isCallOnCallResult(expressionNode);

        boolean isInvocation =
                isInvocationOnVariable(expressionNode, traceSymbol)
                        || isInitForVariable(expressionNode, traceSymbol)
                        || takesOrigin(expressionNode, traceSymbol);
        // an untraceable argument re-scans the method for any call; a known origin call is only
        // connected to the call it is an argument of
        boolean isUnconnectedNoSymbol =
                traceSymbol.is(TraceSymbol.State.NO_SYMBOL) && traceSymbol.getOrigin().isEmpty();

        // Emitting this candidate's own finding is valid on an unconstrained top-level scan
        // (traceSymbol=SYMBOL_IGNORED) or, on a constrained re-scan from a depending-parameter
        // trace (see onDetectedDependingParameter's ENCLOSED_METHOD case), only when this
        // candidate is actually connected to the traced argument. Without this guard, an
        // untraceable argument (e.g. a bare NULL) re-scans the whole enclosing method and
        // spuriously matches every unrelated call the depending rules cover.
        boolean isConstrainedRescan = !traceSymbol.is(TraceSymbol.State.SYMBOL_IGNORED);
        if ((detectionRule.actionFactory() != null || isPassThrough(detectionRule))
                && (!isConstrainedRescan || isInvocation || isUnconnectedNoSymbol)) {
            MethodDetection<AstNode> methodDetection = new MethodDetection<>(expressionNode, null);
            detectionStore.onReceivingNewDetection(methodDetection);
        }

        int index = 0;
        for (Parameter<AstNode> parameter : detectionRule.parameters()) {
            if (!checkCurrentIndexState(
                    index,
                    arguments,
                    isInvocation,
                    isBuilderPattern,
                    traceSymbol,
                    expressionNode)) {
                index++;
                continue;
            }

            AstNode expression = arguments.get(index);

            if (parameter.is(DetectableParameter.class)) {
                DetectableParameter<AstNode> detectableParameter =
                        (DetectableParameter<AstNode>) parameter;
                List<ResolvedValue<Object, AstNode>> resolvedValues =
                        resolveValuesInInnerScope(
                                Object.class, expression, detectableParameter.getiValueFactory());
                if (resolvedValues.isEmpty()) {
                    resolveValuesInOuterScope(expression, detectableParameter);
                } else {
                    resolvedValues.stream()
                            .map(
                                    resolvedValue ->
                                            new ValueDetection<>(
                                                    resolvedValue,
                                                    detectableParameter,
                                                    expressionNode,
                                                    expressionNode))
                            .forEach(detectionStore::onReceivingNewDetection);
                }
            } else if (!parameter.getDetectionRules().isEmpty()) {
                if (CxxAstNodeHelper.isFunctionCall(expression)
                        || CxxAstNodeHelper.isConstructorCall(expression)) {
                    // the argument is itself a call/constructor expression - analyse it directly,
                    // no variable to trace back to an assignment.
                    detectionStore.onDetectedDependingParameter(
                            parameter, expression, DetectionStore.Scope.EXPRESSION);
                } else {
                    // the argument is a variable reference - walk the enclosing method body to
                    // find the call that constructed it. getParameterTraceSymbol needs the
                    // enclosing call (expressionNode), not the argument itself, to resolve the
                    // parameter's symbol via its own argument list.
                    detectionStore.onDetectedDependingParameter(
                            parameter, expressionNode, DetectionStore.Scope.ENCLOSED_METHOD);
                }
            }

            index++;
        }
    }

    /**
     * A rule without an action and without a detectable parameter only links its depending rules to
     * the object it returns, e.g. {@code kctx = EVP_KDF_CTX_new(kdf)} links the calls made on
     * {@code kctx} to the fetched {@code kdf}. Its method detection carries no value of its own.
     */
    private static boolean isPassThrough(@Nonnull DetectionRule<AstNode> detectionRule) {
        return !detectionRule.nextDetectionRules().isEmpty()
                && detectionRule.parameters().stream()
                        .noneMatch(parameter -> parameter.is(DetectableParameter.class));
    }

    private boolean checkCurrentIndexState(
            int index,
            List<AstNode> arguments,
            boolean isInvocation,
            boolean isBuilderPattern,
            @Nonnull TraceSymbol<Symbol> traceSymbol,
            @Nonnull AstNode expressionNode) {
        if (arguments.size() <= index) {
            return false;
        }

        if (traceSymbol.is(TraceSymbol.State.DIFFERENT)) {
            return false;
        }
        if (traceSymbol.is(TraceSymbol.State.SYMBOL)) {
            return isInvocation;
        }
        if (traceSymbol.is(TraceSymbol.State.NO_SYMBOL)) {
            if (traceSymbol.getOrigin().isPresent()) {
                // the result of a known call, connected to the call it is an argument of
                return isInvocation;
            }
            // an untraceable argument: any call that is not assigned to another variable
            Optional<Symbol> assignedSymbol =
                    getAssignedSymbol(expressionNode).map(TraceSymbol::getSymbol);
            return assignedSymbol.isEmpty() || isBuilderPattern;
        }
        return true;
    }

    /**
     * Extracts constructor arguments from an {@code expressionList} node, descending through the
     * {@code initializerList} wrapper that sonar-cxx inserts between {@code expressionList} and the
     * actual {@code initializerClause} children. Without this descent, {@code getChildren()}
     * returns the single {@code initializerList} node instead of the argument nodes themselves.
     */
    @Nonnull
    private List<AstNode> flattenConstructorArgs(@Nullable AstNode expressionList) {
        if (expressionList == null) {
            return Collections.emptyList();
        }
        AstNode initList = expressionList.getFirstChild(CxxGrammarImpl.initializerList);
        if (initList == null) {
            return expressionList.getChildren();
        }
        List<AstNode> out = new LinkedList<>();
        for (AstNode child : initList.getChildren()) {
            if (!",".equals(child.getTokenValue())) {
                out.add(child);
            }
        }
        return out;
    }
}
