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
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.WeakHashMap;
import javax.annotation.CheckForNull;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.sonar.cxx.parser.CxxGrammarImpl;
import org.sonar.cxx.parser.CxxPunctuator;
import org.sonar.cxx.squidbridge.api.AstNodeSymbolExtension;
import org.sonar.cxx.squidbridge.api.Symbol;
import org.sonar.cxx.utils.CxxAstNodeHelper;

/**
 * The calls of a C++ constructor. An object of a class is constructed by a new-expression ({@code
 * new Hasher("SHA224")}), by the declaration of an object with arguments ({@code Hasher
 * h("SHA224")}, {@code Hasher h{"SHA224"}}, {@code Hasher h = {"SHA224"}}) and by an explicit type
 * conversion ({@code Hasher("SHA224")}, {@code Hasher{"SHA224"}}), which constructs a temporary
 * object.
 *
 * <p>The declaration of an object whose arguments are all names, {@code Hasher h(name)}, is read by
 * the parser as the declaration of a function {@code h} with untyped parameters. It constructs an
 * object when the names name values, as C++ reads it, and declares a function when they name types.
 *
 * <p>A name is the name of a class when it resolves to a class, struct or union, or, as a class
 * declared in another namespace is not always resolved, when a class of that name is declared in
 * the translation unit.
 */
public final class CxxConstructorCalls {

    /** The names of the classes declared in a translation unit, by its root node. */
    private static final Map<AstNode, Set<String>> CLASS_NAMES =
            Collections.synchronizedMap(new WeakHashMap<>());

    private CxxConstructorCalls() {
        // private
    }

    /** Whether the node calls a constructor. */
    public static boolean isConstructorCall(@Nullable AstNode node) {
        if (node == null) {
            return false;
        }
        if (node.is(CxxGrammarImpl.newExpression)) {
            return true;
        }
        if (node.is(CxxGrammarImpl.initDeclarator)) {
            return isObjectDeclaration(node);
        }
        return node.is(CxxGrammarImpl.postfixExpression) && isTypeConversion(node);
    }

    /** The arguments passed to the constructor a {@link #isConstructorCall call} calls. */
    @Nonnull
    public static List<AstNode> getArguments(@Nonnull AstNode call) {
        if (call.is(CxxGrammarImpl.newExpression)) {
            final AstNode initializer = call.getFirstChild(CxxGrammarImpl.newInitializer);
            return initializer == null ? List.of() : argumentsOf(initializer);
        }
        if (call.is(CxxGrammarImpl.initDeclarator)) {
            final AstNode initializer = call.getFirstChild(CxxGrammarImpl.initializer);
            if (initializer != null) {
                return argumentsOf(initializer);
            }
            return argumentsReadAsParameters(call);
        }
        if (call.is(CxxGrammarImpl.postfixExpression)) {
            return argumentsOf(call);
        }
        return List.of();
    }

    /**
     * The name of the class a {@link #isConstructorCall call} constructs an object of, as it is
     * written, e.g. {@code crypto::Digest}.
     */
    @CheckForNull
    public static String getClassName(@Nonnull AstNode call) {
        if (call.is(CxxGrammarImpl.newExpression)) {
            final AstNode typeId = call.getFirstChild(CxxGrammarImpl.newTypeId);
            final AstNode type =
                    typeId == null ? null : typeId.getFirstDescendant(CxxGrammarImpl.typeName);
            return type == null ? null : textOf(typeNameOf(type));
        }
        if (call.is(CxxGrammarImpl.initDeclarator)) {
            final AstNode type = declaredType(call);
            return type == null ? null : textOf(type);
        }
        if (call.is(CxxGrammarImpl.postfixExpression)) {
            return textOf(call.getFirstChild());
        }
        return null;
    }

    /**
     * The name of the class a variable, a pointer or a reference is declared with, e.g. {@code
     * Hasher} for {@code Hasher &h} or {@code crypto::Digest} for {@code crypto::Digest *d}, or
     * null when its type is not a class.
     */
    @CheckForNull
    public static String getDeclaredClassName(@Nonnull Symbol.VariableSymbol variable) {
        final Symbol.TypeSymbol declaredType = variable.declaredType();
        if (declaredType != null && declaredType.fullyQualifiedName() != null) {
            return declaredType.fullyQualifiedName();
        }
        AstNode declaration = variable.declaration();
        while (declaration != null
                && !declaration.is(
                        CxxGrammarImpl.simpleDeclaration,
                        CxxGrammarImpl.parameterDeclaration,
                        CxxGrammarImpl.memberDeclaration)) {
            declaration = declaration.getParent();
        }
        if (declaration == null) {
            return null;
        }
        final AstNode specifiers =
                declaration.getFirstChild(
                        CxxGrammarImpl.declSpecifierSeq,
                        CxxGrammarImpl.declSpecifier,
                        CxxGrammarImpl.memberDeclSpecifierSeq,
                        CxxGrammarImpl.parameterDeclSpecifierSeq);
        if (specifiers == null) {
            return null;
        }
        final AstNode qualified = specifiers.getFirstDescendant(CxxGrammarImpl.simpleTypeSpecifier);
        if (qualified != null && qualified.hasDirectChildren(CxxGrammarImpl.typeName)) {
            return textOf(qualified);
        }
        final AstNode type = specifiers.getFirstDescendant(CxxGrammarImpl.typeName);
        return type == null ? null : textOf(type);
    }

    /**
     * Whether a name written at the given node names a class; of a qualified name, e.g. {@code
     * crypto::Digest}, its last component is the name of the class.
     */
    public static boolean namesAClass(@Nonnull AstNode node, @Nonnull String name) {
        final Symbol symbol = AstNodeSymbolExtension.getSymbol(node);
        if (symbol instanceof Symbol.TypeSymbol type && !symbol.isUnknown()) {
            return type.isClass() || type.isStruct() || type.isUnion();
        }
        final int qualifier = name.lastIndexOf("::");
        final String simpleName = qualifier < 0 ? name : name.substring(qualifier + 2);
        return classNamesOf(rootOf(node)).contains(simpleName);
    }

    /**
     * Whether two names of a class name the same class: they are equal, or one is the other
     * qualified by namespaces or classes, e.g. {@code Digest} written inside {@code namespace
     * crypto} and {@code crypto::Digest}.
     */
    public static boolean isSameClass(@Nonnull String name, @Nonnull String other) {
        return name.equals(other) || name.endsWith("::" + other) || other.endsWith("::" + name);
    }

    /** The name of a class or namespace written in tokens, e.g. {@code crypto::Digest}. */
    @Nonnull
    public static String textOf(@Nonnull AstNode node) {
        final StringBuilder text = new StringBuilder();
        node.getTokens().forEach(token -> text.append(token.getValue()));
        return text.toString();
    }

    /**
     * Whether an init-declarator declares an object of a class with constructor arguments: neither
     * a pointer, a reference nor an array, initialized with arguments in parentheses or braces, or
     * read as a function declaration whose parameters are arguments.
     */
    private static boolean isObjectDeclaration(@Nonnull AstNode initDeclarator) {
        final AstNode declarator = initDeclarator.getFirstChild(CxxGrammarImpl.declarator);
        if (declarator == null || !declaresAnObject(declarator)) {
            return false;
        }
        final AstNode initializer = initDeclarator.getFirstChild(CxxGrammarImpl.initializer);
        final boolean hasArguments =
                initializer != null
                        ? initializer.getFirstChild().is(CxxPunctuator.BR_LEFT)
                                || initializer.getLastChild().is(CxxGrammarImpl.bracedInitList)
                        : !argumentsReadAsParameters(initDeclarator).isEmpty();
        if (!hasArguments) {
            return false;
        }
        final AstNode type = declaredType(initDeclarator);
        return type != null && namesAClass(lastIdentifier(type), textOf(type));
    }

    /** Whether a declarator declares an object, not a pointer, a reference or an array. */
    private static boolean declaresAnObject(@Nonnull AstNode declarator) {
        final AstNode first = declarator.getFirstChild();
        if (first.is(CxxGrammarImpl.ptrDeclarator)
                && first.hasDirectChildren(CxxGrammarImpl.ptrOperator)) {
            return false;
        }
        return !(first.is(CxxGrammarImpl.noptrDeclarator)
                && first.hasDirectChildren(CxxPunctuator.SQBR_LEFT));
    }

    /**
     * The arguments of a constructor call the parser read as the untyped parameters of a function
     * declaration, {@code name} in {@code Hasher h(name)}, see {@link
     * CxxAstNodeHelper#getUntypedParameters}: the names of the parameters, when each names a value.
     * Empty when the declarator declares a function, or is not read as one.
     */
    @Nonnull
    private static List<AstNode> argumentsReadAsParameters(@Nonnull AstNode initDeclarator) {
        final List<AstNode> arguments = new ArrayList<>();
        for (AstNode parameter :
                CxxAstNodeHelper.getUntypedParameters(
                        initDeclarator.getFirstChild(CxxGrammarImpl.declarator))) {
            final AstNode name = CxxAstNodeHelper.getUntypedParameterName(parameter);
            final Symbol symbol = name == null ? null : AstNodeSymbolExtension.getSymbol(name);
            if (symbol == null || symbol.isUnknown() || symbol.isTypeSymbol()) {
                return List.of();
            }
            arguments.add(name);
        }
        return arguments;
    }

    /**
     * The type of the object an init-declarator declares when it is a class named by its
     * declaration, e.g. {@code Hasher} or {@code crypto::Digest}, or null.
     */
    @CheckForNull
    private static AstNode declaredType(@Nonnull AstNode initDeclarator) {
        final AstNode list = initDeclarator.getParent();
        final AstNode declaration = list == null ? null : list.getParent();
        if (declaration == null || !declaration.is(CxxGrammarImpl.simpleDeclaration)) {
            return null;
        }
        final AstNode specifiers =
                declaration.hasDirectChildren(CxxGrammarImpl.declSpecifierSeq)
                        ? declaration.getFirstChild(CxxGrammarImpl.declSpecifierSeq)
                        : declaration;
        for (AstNode specifier : specifiers.getChildren(CxxGrammarImpl.declSpecifier)) {
            final AstNode type = specifier.getFirstChild();
            if (type.is(CxxGrammarImpl.typeName)) {
                return type;
            }
            if (type.is(CxxGrammarImpl.simpleTypeSpecifier)
                    && type.hasDirectChildren(CxxGrammarImpl.typeName)) {
                return type;
            }
        }
        return null;
    }

    /**
     * Whether a postfix expression is an explicit type conversion to a class, {@code Hasher("x")}
     * or {@code Hasher{"x"}}: a class name followed by arguments in parentheses or braces.
     */
    private static boolean isTypeConversion(@Nonnull AstNode postfixExpression) {
        final List<AstNode> children = postfixExpression.getChildren();
        final AstNode type = children.get(0);
        if (!type.is(CxxGrammarImpl.typeName)
                && !(type.is(CxxGrammarImpl.simpleTypeSpecifier)
                        && type.hasDirectChildren(CxxGrammarImpl.typeName))) {
            return false;
        }
        final boolean parenthesized =
                children.size() >= 3
                        && children.size() <= 4
                        && children.get(1).is(CxxPunctuator.BR_LEFT)
                        && children.get(children.size() - 1).is(CxxPunctuator.BR_RIGHT);
        final boolean braced =
                children.size() == 2 && children.get(1).is(CxxGrammarImpl.bracedInitList);
        return (parenthesized || braced) && namesAClass(lastIdentifier(type), textOf(type));
    }

    /**
     * The arguments in parentheses or braces of a constructor call: of a new-initializer, an
     * initializer, or an explicit type conversion.
     */
    @Nonnull
    private static List<AstNode> argumentsOf(@Nonnull AstNode node) {
        final AstNode braced = node.getFirstChild(CxxGrammarImpl.bracedInitList);
        if (braced != null) {
            return CxxSemantic.elementsOf(braced);
        }
        final AstNode list = node.getFirstChild(CxxGrammarImpl.expressionList);
        if (list == null) {
            return List.of();
        }
        final AstNode clauses = list.getFirstChild(CxxGrammarImpl.initializerList);
        if (clauses == null) {
            return list.getChildren();
        }
        return clauses.getChildren().stream()
                .filter(clause -> !clause.is(CxxPunctuator.COMMA))
                .toList();
    }

    /** The type name of a new-type-id, qualified when it is, e.g. {@code crypto::Digest}. */
    @Nonnull
    private static AstNode typeNameOf(@Nonnull AstNode typeName) {
        final AstNode parent = typeName.getParent();
        return parent != null && parent.is(CxxGrammarImpl.simpleTypeSpecifier) ? parent : typeName;
    }

    @Nonnull
    private static AstNode lastIdentifier(@Nonnull AstNode type) {
        final List<AstNode> identifiers = type.getDescendants(GenericTokenType.IDENTIFIER);
        return identifiers.isEmpty() ? type : identifiers.get(identifiers.size() - 1);
    }

    @Nonnull
    private static AstNode rootOf(@Nonnull AstNode node) {
        AstNode root = node;
        while (root.getParent() != null) {
            root = root.getParent();
        }
        return root;
    }

    @Nonnull
    private static Set<String> classNamesOf(@Nonnull AstNode root) {
        return CLASS_NAMES.computeIfAbsent(
                root,
                unit -> {
                    final Set<String> names = new HashSet<>();
                    for (AstNode specifier : unit.getDescendants(CxxGrammarImpl.classSpecifier)) {
                        final String name = CxxAstNodeHelper.getClassName(specifier);
                        if (name != null) {
                            names.add(name);
                        }
                    }
                    return names;
                });
    }
}
