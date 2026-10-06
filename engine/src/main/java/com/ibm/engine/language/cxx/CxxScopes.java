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

import com.sonar.cxx.sslr.api.AstNode;
import com.sonar.cxx.sslr.api.GenericTokenType;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import javax.annotation.CheckForNull;
import javax.annotation.Nonnull;
import org.sonar.cxx.parser.CxxGrammarImpl;
import org.sonar.cxx.utils.CxxAstNodeHelper;

/**
 * The namespaces and classes C++ code is in, by which a call and the function it calls are named
 * alike: a function is named with the namespaces it is declared in, e.g. {@code util::digest}, and
 * a call by the names C++ name lookup tries for it, the name as written qualified by each namespace
 * the call is in, innermost first, and as written.
 */
public final class CxxScopes {

    private CxxScopes() {
        // private
    }

    /**
     * The namespaces a node is in, outermost first, e.g. {@code [util, inner]} inside {@code
     * namespace util { namespace inner { ... } }} or {@code namespace util::inner { ... }}.
     */
    @Nonnull
    public static List<String> enclosingNamespaces(@Nonnull AstNode node) {
        final List<String> namespaces = new LinkedList<>();
        for (AstNode scope = node.getParent(); scope != null; scope = scope.getParent()) {
            if (scope.is(
                    CxxGrammarImpl.namedNamespaceDefinition,
                    CxxGrammarImpl.nestedNamespaceDefinition)) {
                final AstNode name = scope.getFirstChild(GenericTokenType.IDENTIFIER);
                if (name != null) {
                    namespaces.add(0, name.getTokenValue());
                }
                final AstNode enclosing =
                        scope.getFirstChild(CxxGrammarImpl.enclosingNamespaceSpecifier);
                if (enclosing != null) {
                    namespaces.add(0, CxxConstructorCalls.textOf(enclosing));
                }
            }
        }
        return namespaces;
    }

    /**
     * The names C++ name lookup tries for a call of a function named {@code name} as written at the
     * call: the name qualified by each namespace the call is in, innermost first, then the name as
     * written, e.g. {@code util::inner::digest}, {@code util::digest} and {@code digest} for {@code
     * digest(...)} inside {@code namespace util { namespace inner { ... } }}.
     */
    @Nonnull
    public static List<String> lookupNames(@Nonnull AstNode call, @Nonnull String name) {
        final List<String> namespaces = enclosingNamespaces(call);
        final List<String> names = new ArrayList<>();
        for (int i = namespaces.size(); i > 0; i--) {
            names.add(String.join("::", namespaces.subList(0, i)) + "::" + name);
        }
        names.add(name);
        return names;
    }

    /**
     * The class a function definition defines a member function of, named with the namespaces and
     * classes it is declared in, e.g. {@code crypto::Digest}, or null for a function that is not a
     * member of a class: a function defined in its class, or outside it with a name qualified by a
     * class, e.g. {@code Hasher::reset}.
     */
    @CheckForNull
    public static String classOfFunction(@Nonnull AstNode functionDefinition) {
        final String functionName = CxxAstNodeHelper.getFunctionDefinitionName(functionDefinition);
        if (functionName == null) {
            return null;
        }
        final List<String> scopes = new LinkedList<>(enclosingNamespaces(functionDefinition));
        int classes = 0;
        for (AstNode scope = functionDefinition.getParent();
                scope != null;
                scope = scope.getParent()) {
            if (scope.is(CxxGrammarImpl.classSpecifier)) {
                final String name = CxxAstNodeHelper.getClassName(scope);
                if (name == null) {
                    return null;
                }
                // the enclosing classes are met innermost first
                scopes.add(scopes.size() - classes, name);
                classes++;
            }
        }
        final int separator = functionName.lastIndexOf("::");
        if (separator > 0) {
            final String qualifier = functionName.substring(0, separator);
            final AstNode declaratorId =
                    functionDefinition
                            .getFirstChild(CxxGrammarImpl.declarator)
                            .getFirstDescendant(CxxGrammarImpl.declaratorId);
            final List<AstNode> identifiers =
                    declaratorId.getDescendants(GenericTokenType.IDENTIFIER);
            if (identifiers.size() >= 2
                    && CxxConstructorCalls.namesAClass(
                            identifiers.get(identifiers.size() - 2), qualifier)) {
                scopes.add(qualifier);
                return String.join("::", scopes);
            }
        }
        return classes > 0 ? String.join("::", scopes) : null;
    }

    /** The class of the member function a node is in, see {@link #classOfFunction}, or null. */
    @CheckForNull
    public static String classOfEnclosingFunction(@Nonnull AstNode node) {
        final AstNode function = CxxAstNodeHelper.getEnclosingFunction(node);
        return function == null ? null : classOfFunction(function);
    }

    /**
     * Whether the class of the given name, declared in the translation unit of the node, declares a
     * member of the given name, e.g. a member function.
     */
    public static boolean declaresMember(
            @Nonnull AstNode node, @Nonnull String className, @Nonnull String member) {
        AstNode root = node;
        while (root.getParent() != null) {
            root = root.getParent();
        }
        final String simpleName = className.substring(className.lastIndexOf(':') + 1);
        for (AstNode specifier : root.getDescendants(CxxGrammarImpl.classSpecifier)) {
            if (!simpleName.equals(CxxAstNodeHelper.getClassName(specifier))) {
                continue;
            }
            for (AstNode declaratorId : specifier.getDescendants(CxxGrammarImpl.declaratorId)) {
                if (declaratorId.getFirstAncestor(CxxGrammarImpl.classSpecifier) == specifier
                        && !declaratorId.hasAncestor(CxxGrammarImpl.parameterDeclaration)
                        && !declaratorId.hasAncestor(CxxGrammarImpl.functionBody)
                        && member.equals(CxxConstructorCalls.textOf(declaratorId))) {
                    return true;
                }
            }
        }
        return false;
    }
}
