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
package com.ibm.mapper.model;

import static java.util.Map.entry;

import com.ibm.mapper.model.algorithms.AES;
import com.ibm.mapper.model.algorithms.Argon2;
import com.ibm.mapper.model.algorithms.HQC;
import com.ibm.mapper.model.algorithms.blake.BLAKE2X;
import com.ibm.mapper.model.algorithms.blake.BLAKE2b;
import com.ibm.mapper.model.collections.AssetCollection;
import com.ibm.mapper.model.collections.CipherSuiteCollection;
import com.ibm.mapper.model.collections.IdentifierCollection;
import com.ibm.mapper.model.collections.MergeableCollection;
import com.ibm.mapper.utils.DetectionLocation;
import java.io.File;
import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Modifier;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Supplier;
import java.util.stream.Stream;
import javax.annotation.Nonnull;

/** The concrete node classes of the model, and a node of each of them, for the model tests. */
final class ModelNodes {

    static final DetectionLocation TEST =
            new DetectionLocation("testfile", 1, 1, List.of("test"), () -> "TEST");

    /**
     * The node classes whose constructors take other arguments than a detection location, numbers
     * and names; every other class is built from its constructor with the fewest such arguments.
     */
    private static final Map<Class<? extends INode>, Supplier<INode>> BUILT_EXPLICITLY =
            Map.ofEntries(
                    entry(Algorithm.class, () -> new Algorithm("TEST", BlockCipher.class, TEST)),
                    entry(Key.class, () -> new Key(new AES(TEST))),
                    entry(PrivateKey.class, () -> new PrivateKey(new Key(new AES(TEST)))),
                    entry(PublicKey.class, () -> new PublicKey(new Key(new AES(TEST)))),
                    entry(SecretKey.class, () -> new SecretKey(new Key(new AES(TEST)))),
                    entry(Argon2.class, () -> new Argon2(Argon2.Variant.ID, TEST)),
                    entry(HQC.class, () -> new HQC(KeyEncapsulationMechanism.class, TEST)),
                    entry(BLAKE2X.class, () -> new BLAKE2X(new BLAKE2b(TEST), TEST)),
                    entry(AssetCollection.class, () -> new AssetCollection(List.of(new AES(TEST)))),
                    entry(
                            CipherSuiteCollection.class,
                            () ->
                                    new CipherSuiteCollection(
                                            List.of(
                                                    new CipherSuite(
                                                            "TLS_AES_128_GCM_SHA256", TEST)))),
                    entry(
                            IdentifierCollection.class,
                            () ->
                                    new IdentifierCollection(
                                            List.of(new Identifier("x25519", TEST)))),
                    entry(
                            MergeableCollection.class,
                            () -> new MergeableCollection(List.of(new AES(TEST)))));

    private ModelNodes() {
        // utility class
    }

    /**
     * A node of the class, built by {@link #BUILT_EXPLICITLY} or by its constructor with the fewest
     * arguments that only takes a detection location, numbers and names.
     */
    @Nonnull
    static INode build(@Nonnull Class<? extends INode> nodeClass) {
        final Supplier<INode> explicit = BUILT_EXPLICITLY.get(nodeClass);
        if (explicit != null) {
            return explicit.get();
        }
        return Arrays.stream(nodeClass.getConstructors())
                .sorted(Comparator.comparingInt(Constructor::getParameterCount))
                .map(ModelNodes::buildWith)
                .flatMap(Optional::stream)
                .findFirst()
                .orElseThrow(
                        () ->
                                new AssertionError(
                                        nodeClass.getName()
                                                + " has no constructor this test can use:"
                                                + " add it to BUILT_EXPLICITLY"));
    }

    /** The concrete classes of the model, read from the directory it is compiled to. */
    @Nonnull
    static List<Class<? extends INode>> concreteNodeClasses()
            throws IOException, URISyntaxException {
        final Path classes =
                Path.of(INode.class.getProtectionDomain().getCodeSource().getLocation().toURI());
        final Path model = classes.resolve(INode.class.getPackageName().replace('.', '/'));
        try (Stream<Path> files = Files.walk(model)) {
            return files.map(classes::relativize)
                    .map(Path::toString)
                    .filter(file -> file.endsWith(".class") && !file.contains("$"))
                    .map(
                            file ->
                                    file.substring(0, file.length() - ".class".length())
                                            .replace(File.separatorChar, '.'))
                    .sorted()
                    .<Class<?>>map(ModelNodes::load)
                    .filter(INode.class::isAssignableFrom)
                    .filter(type -> !type.isInterface())
                    .filter(type -> !Modifier.isAbstract(type.getModifiers()))
                    .<Class<? extends INode>>map(type -> type.asSubclass(INode.class))
                    .toList();
        }
    }

    /**
     * The node built by the constructor, when it only takes a detection location, numbers and
     * names.
     */
    @Nonnull
    private static Optional<INode> buildWith(@Nonnull Constructor<?> constructor) {
        final Class<?>[] types = constructor.getParameterTypes();
        final Object[] arguments = new Object[types.length];
        for (int i = 0; i < types.length; i++) {
            if (types[i] == DetectionLocation.class) {
                arguments[i] = TEST;
            } else if (types[i] == int.class || types[i] == Integer.class) {
                arguments[i] = 128;
            } else if (types[i] == String.class) {
                arguments[i] = "TEST";
            } else {
                return Optional.empty();
            }
        }
        try {
            return Optional.of((INode) constructor.newInstance(arguments));
        } catch (InstantiationException | IllegalAccessException | InvocationTargetException e) {
            return Optional.empty();
        }
    }

    @Nonnull
    private static Class<?> load(@Nonnull String className) {
        try {
            return Class.forName(className);
        } catch (ClassNotFoundException e) {
            throw new IllegalStateException(className, e);
        }
    }
}
