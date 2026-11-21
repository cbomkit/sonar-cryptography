# Repository Guidelines

## Project Structure & Module Organization

This is a Java 17, multi-module Maven project. `plugin-core/` holds the SonarQube plugin code. `java/`, `python/`, `go/`, and `csharp/` implement language detection; each registers an `ILanguageModule` service; `engine/` provides shared detection logic. `mapper/`, `enricher/`, and `output/` turn findings into a cryptographic bill of materials. Shared code lives in `common/` and `rules/`. `distribution/` packages the three variants: `distribution/plugin` (default), `distribution/plugin-with-go` and `distribution/library`. Each module keeps production code in `src/main/java` and tests in `src/test/java`; language test inputs live under `src/test/files/`. See `docs/` for rule and language-extension guides.

## Build Variants

One root `pom.xml`; profiles only add modules. `plugin` (active by default) builds `distribution/plugin`. `with-go` adds `go/` and `distribution/plugin-with-go`; it bundles SSALv1-licensed sonar-go, so its JAR is for private use only and is never published. `lib` adds `distribution/library`, which bundles the LGPL-3.0 sonar-java and sonar-python. Naming any profile with `-P` turns `plugin` off. Do not combine `plugin` and `with-go`. When a GitHub release is published, `.github/workflows/maven-publish.yml` attaches the `plugin` JAR to the release and deploys the `lib` variant to GitHub Packages with `mvn deploy -Plib`. Do not deploy, release or publish anything yourself; a deploy dry run must use `-DaltDeploymentRepository=dry::file:///tmp/...`. Main code must use only the public analyzer API (Checkstyle `IllegalImport`); compile versions in `pom.xml` are the last LGPL releases, so do not upgrade them without a licence review.

## Build, Test, and Development Commands

- `mvn clean package`: build all modules and run tests for the default `plugin` variant, as CI does.
- `mvn clean package -Pwith-go` / `mvn clean package -Plib`: build the Go or library variant instead (CI builds all three).
- `mvn test`: run the test suite without packaging.
- `mvn test -pl java`: run one module's tests; replace `java` with another module name.
- `mvn test -pl go -am -Pwith-go`: run the Go module's tests; `go` is only in the build with `-Pwith-go`.
- `python3 distribution/src/test/python/verify_analyzer_packaging.py --variant {plugin,plugin-with-go,library} <jar>`: check a variant JAR's licences and contents.
- `mvn spotless:check`: check Java formatting and license headers.
- `mvn spotless:apply`: format Java files and apply required headers.
- `mvn checkstyle:check`: check Java style rules.
- `docker-compose up`: start the local PostgreSQL and SonarQube services after building the plugin.

## Coding Style & Naming Conventions

Use Spotless's Google Java Format in AOSP style for Java indentation, imports, and annotations. Keep the Apache 2.0 license header on Java files. Follow existing package names in lowercase, Java types in `UpperCamelCase`, and methods and fields in `lowerCamelCase`. Checkstyle runs during Maven's `validate` phase; run formatting and style checks before submitting changes.

## Testing Guidelines

Tests use JUnit 5 and AssertJ. Name test classes `*Test.java` and place them beside the corresponding module's code under `src/test/java`. For detection rules, add representative source fixtures under that module's `src/test/files/` and assert the detected findings. Run `mvn test` for broad changes or `mvn test -pl <module>` for focused changes. No numeric coverage threshold is configured in the parent build.

## Writing C# Detection Rules

Declare a rule's parameters with `withNamedMethodParameter` / `withOptionalNamedMethodParameter` using the real .NET parameter names rather than positionally. A rule that declares any named parameter is matched without an arity constraint, and `CSharpNamedArgumentBinder` resolves the overload by binding each parameter by keyword, then by position, then by unique declared type. That is what lets one rule per method cover every overload, place a value correctly when an overload reorders it, and still refuse to guess.

Write one rule per method, not one per arity: two rules on the same method would both match and the call would be detected twice. Mark a parameter required only if every overload has it, since the rule accepts argument counts between the required count and the declared count. Declare a distinctive type (`"HashAlgorithmName"`, `"RSASignaturePadding"`, `"int"`) wherever one exists, because the type is what places a value when the position varies and what rejects an argument that cannot be it. Every new test should also assert the *absence* of a value that cannot be resolved, via `assertNoChild` or a typed `null` passed to `assertChild`: a guessed parameter is worse than a missing one.

## Commits & Pull Requests

Recent commits commonly use short subjects such as `feat: ...`, `fix: ...`, `ci: ...`, and `chore(deps): ...`; some use plain descriptive subjects. Keep the subject specific and include an issue or PR reference when applicable. In pull requests, describe the behavior changed, affected modules, and commands run; link the relevant issue. Add screenshots only for visible SonarQube interface changes.
