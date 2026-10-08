# Sonar Cryptography Plugin (CBOMkit-hyperion)

[![License](https://img.shields.io/github/license/cbomkit/sonar-cryptography.svg?)](https://opensource.org/licenses/Apache-2.0) <!--- long-description-skip-begin -->
[![Current Release](https://img.shields.io/github/release/cbomkit/sonar-cryptography.svg?logo=IBM)](https://github.com/cbomkit/sonar-cryptography/releases)


This repository contains a SonarQube Plugin that detects cryptographic assets
in source code and generates [CBOM](https://cyclonedx.org/capabilities/cbom/).
It is part of **the [CBOMKit](https://github.com/cbomkit) toolset**.

## Table of Contents

- [Version compatibility](#version-compatibility)
- [Supported languages and libraries](#supported-languages-and-libraries)
- [Installation](#installation)
- [Using](#using)
- [Example Output](#example-output)
- [Build](#build)
- [Help and troubleshooting](#help-and-troubleshooting)
- [Contribution Guidelines](#contribution-guidelines)
- [License](#license)

## Version compatibility

| Plugin Version  | SonarQube Version              |
|-----------------|--------------------------------|
| 1.3.7 and up    | SonarQube 9.9 (LTS) and up     |
| 1.3.2 and 1.3.6 | SonarQube 9.8 (LTS) up to 10.8 | 
| 1.2.0 to 1.3.1  | SonarQube 9.8 (LTS) up to 10.4 |      


## Supported languages and libraries

| Language | Cryptographic Library                                                                         | Coverage         |
|----------|-----------------------------------------------------------------------------------------------|------------------|
| Java     | [JCA](https://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html) | 100%             |
|          | [BouncyCastle](https://github.com/bcgit/bc-java) (*light-weight API*)                         | 100%[^1]         |
| Python   | [pyca/cryptography](https://cryptography.io/en/latest/)                                       | 100%             |
| Go       | [crypto](https://pkg.go.dev/crypto) (*standard library*)                                      | 100%[^2]         |
|          | [golang.org/x/crypto](https://pkg.go.dev/golang.org/x/crypto)                                 | Partial[^3]      |
| C#       | [System.Security.Cryptography](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography) | In development[^4] |

[^1]: We only cover the BouncyCastle *light-weight API* according to [this specification](https://javadoc.io/static/org.bouncycastle/bctls-jdk14/1.80/specifications.html)
[^2]: All packages under [`crypto`](https://pkg.go.dev/crypto@go1.25.6#section-directories) are covered except `crypto/x509`
[^3]: Covers `golang.org/x/crypto/hkdf`, `golang.org/x/crypto/pbkdf2`, and `golang.org/x/crypto/sha3`
[^4]: C# support uses a custom ANTLR grammar (targeting up to C# 13; published from [github.com/fynnth/cbomkit-csharp-parser](https://github.com/fynnth/cbomkit-csharp-parser)) to parse source files directly. Detection rules cover 95 of the 97 algorithm-bearing classes of `System.Security.Cryptography`; the two exceptions, `CryptoStream` and `PemEncoding`, name no algorithm of their own. **Not yet meant for production usage!** Beyond the algorithm, the rules capture the parameters that decide whether a component is sound: key sizes, elliptic curves, PBKDF2 and HKDF iteration counts, salt and derived-key lengths, signature digests, RSA signature and OAEP paddings including the OAEP digest, AEAD nonce and tag lengths, cipher modes and paddings, and post-quantum parameter sets. Parameters are matched by their .NET names and declared types rather than by argument position, so a value is placed correctly across overloads that reorder it and across keyword arguments written out of order. The engine resolves a value when it is syntactically certain: literals, locals with a single assignment, `const`s, class fields the class never reassigns, `new byte[n]` and `stackalloc byte[n]` lengths, simple arithmetic, and — file-wide — a parameter whose callers all pass the same value and a call to a local method with a single return value. Object initializers, alias variables, chained calls and expression-bodied members are understood; control flow inside a method (`if`/`for`/`while`/`using`/`try`/`lock`/`fixed`/`switch`) does not interrupt variable tracking; and code inside a `#if` region is analysed, in every branch where that is valid C# and otherwise in the first branch of each chain, since a bill of materials should list the cryptography a build configuration can reach without losing the file when a conditional splits a single construct. The static one-shot helpers `HashData` and `TryHashData` are detected in their own right, because they have no creation call for an algorithm to be attached to. A creation that is not a statement of its own is a call site too: a field or auto-property initializer, one handed straight to another constructor or method, and object- and collection-initializer values. A key taken from an X.509 certificate is recorded as private or public key material — in both the extension-method and the static spelling of those accessors — so a CBOM reader can tell a key whose length only the certificate knows from one the engine failed to resolve. **Known limitations:** nothing resolves across file boundaries; there is no semantic type checker, so two overloads that share an arity and differ only in a parameter type this engine cannot tell apart are not separated; and values that depend on evaluating control flow (a ternary with differing branches, an element access, a `switch` expression) are deliberately left unresolved rather than guessed. Three expression forms hide a call site altogether rather than only its parameters: an `as` cast applied to the result, a `??=` coalescing assignment, and a creation written inside a `switch` expression arm.

> [!NOTE]
> The plugin is designed in a modular way so that it can be extended to support additional languages and recognition rules to support more libraries.
> - To add support for another language or cryptography library, see [*Extending the Sonar Cryptography Plugin to add support for another language or cryptography library*](./docs/LANGUAGE_SUPPORT.md)
> - If you just want to know more about the syntax for writing new detection rules, see [*Writing new detection rules for the Sonar Cryptography Plugin*](./docs/DETECTION_RULE_STRUCTURE.md)

## Installation

> [!NOTE] 
> To run the plugin, you need a running SonarQube instance with one of the supported 
> versions. If you don't have one but want to try the plugin, you can use the
> included Docker Compose to set up a development environment. See 
> [here](CONTRIBUTING.md#build) for instructions.

Copy the plugin (the JAR file from the [latest releases](https://github.com/cbomkit/sonar-cryptography/releases))
to `$SONARQUBE_HOME/extensions/plugins` and restart 
SonarQube ([more](https://docs.sonarqube.org/latest/setup-and-upgrade/install-a-plugin/)).

## Using

The plugin provides new rules regarding the use of cryptography for the supported languages.
They are grouped in the **Sonar Cryptography** rule repositories, one per language
(`sonar-java-crypto`, `sonar-python-crypto` and `sonar-go-crypto`).
If you enable the *Cryptographic Inventory (CBOM)* rule, a source code scan creates a cryptographic
inventory by creating a [CBOM](https://cyclonedx.org/capabilities/cbom/) with all cryptographic
assets and writing a `cbom.json` to the scan directory.

### Add Cryptography Rules to your Quality Profile

This plugin incorporates rules specifically focused on cryptography.

> To generate a Cryptography Bill of Materials (CBOM), it is mandatory to activate the
> *Cryptographic Inventory (CBOM)* rule.

![Activate Rules Crypto Rules](docs/images/rules.png)

The plugin currently ships these rules:

| Rule                                                     | Languages        | Contributes to the CBOM |
|----------------------------------------------------------|------------------|-------------------------|
| *Cryptographic Inventory (CBOM)*                         | Java, Python, Go | yes                     |
| *Do not use MD5 for cryptographic purposes like hashing* | Java, Python     | no                      |

Only the *Cryptographic Inventory (CBOM)* rule writes a `cbom.json`; the other rules just raise
issues on the scanned code. Future updates may introduce additional rules to expand functionality.

### Scan Source Code

Now you can follow the [SonarQube documentation](https://docs.sonarqube.org/latest/analyzing-source-code/overview/) 
to start your first scan.

### Configuration

| Property                   | Default | Scope   | Description                                                                   |
|----------------------------|---------|---------|-------------------------------------------------------------------------------|
| `sonar.cryptoScanner.cbom` | `cbom`  | Project | Filename (without extension) of the generated CBOM, written as `<name>.json`. |

The property can be set in the SonarQube UI under *Project Settings → General*, or passed to the
scanner directly:

```bash
sonar-scanner -Dsonar.cryptoScanner.cbom=my-cbom
```

### Visualizing your CBOM

Once you have scanned your source code with the plugin, and obtained a `cbom.json` file, you can use [CBOMkit](https://github.com/cbomkit/cbomkit) service to know more about it.
It provides you with general insights about the cryptography used in your source code and its compliance with post-quantum safety.
It also allows you to explore precisely each cryptography asset and its detailed specification, and displays where it appears in your code.

## Example Output

The plugin generates a `cbom.json` file in [CycloneDX CBOM format](https://cyclonedx.org/capabilities/cbom/). Here's an example showing detected cryptographic assets:

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "version": 1,
  "metadata": {
    "timestamp": "2026-01-20T10:58:39Z",
    "tools": {
      "services": [
        {
          "name": "CBOMkit",
          "provider": { "name": "PQCA" }
        }
      ]
    }
  },
  "components": [
    {
      "name": "SHA256",
      "type": "cryptographic-asset",
      "bom-ref": "0f4f522b-ef99-43b7-9f98-6e83b3b233ca",
      "evidence": {
        "occurrences": [
          {
            "line": 51,
            "location": "src/main/java/com/example/EncryptionConfig.java",
            "additionalContext": "java.security.MessageDigest#getInstance"
          }
        ]
      },
      "cryptoProperties": {
        "oid": "2.16.840.1.101.3.4.2.1",
        "assetType": "algorithm",
        "algorithmProperties": {
          "primitive": "hash",
          "cryptoFunctions": ["digest"],
          "parameterSetIdentifier": "256"
        }
      }
    },
    {
      "name": "AES128-GCM",
      "type": "cryptographic-asset",
      "bom-ref": "e006c3f1-912a-4de5-8399-79bf0f350cb9",
      "evidence": {
        "occurrences": [
          {
            "line": 29,
            "location": "src/main/java/com/example/aes/AESGCM.java",
            "additionalContext": "javax.crypto.Cipher#getInstance"
          }
        ]
      },
      "cryptoProperties": {
        "oid": "2.16.840.1.101.3.4.1",
        "assetType": "algorithm",
        "algorithmProperties": {
          "mode": "gcm",
          "primitive": "ae",
          "cryptoFunctions": ["decrypt"],
          "parameterSetIdentifier": "128"
        }
      }
    },
    {
      "name": "RSA-OAEP",
      "type": "cryptographic-asset",
      "bom-ref": "ff238e09-dd3d-44c4-ad49-34350f1d9cc7",
      "cryptoProperties": {
        "oid": "1.2.840.113549.1.1.7",
        "assetType": "algorithm",
        "algorithmProperties": {
          "mode": "ecb",
          "padding": "oaep",
          "primitive": "pke",
          "parameterSetIdentifier": "2048"
        }
      }
    }
  ],
  "dependencies": [
    {
      "ref": "secret-key-ref",
      "dependsOn": ["AES128-ref"]
    }
  ]
}
```

The CBOM includes:
- **Algorithms**: Hash functions, ciphers, key exchange mechanisms with their parameters
- **Keys and secrets**: Private keys, secret keys, and other cryptographic materials
- **Evidence**: Source file locations where each asset was detected
- **Dependencies**: Relationships between cryptographic assets (e.g., a secret key depending on an algorithm)

## Build

```bash
# Build with tests
mvn clean package

# Build without tests (faster)
mvn clean package -DskipTests

# Build specific module
mvn clean package -pl java

# Format code (Google Java Format, AOSP style)
mvn spotless:apply

# Check formatting
mvn spotless:check
```

<details>
<summary><strong>Adding packages to sonar-go-to-slang (Go support)</strong></summary>

Go cryptographic detection relies on [sonar-go-to-slang](https://github.com/SonarSource/sonar-go/tree/master/sonar-go-to-slang) for type resolution. The default binary includes common packages, but some cryptographic packages may require you to rebuild it with additional package export data.

### When is this needed?

If you see "undefined: \<identifier\>" errors during type checking for packages like `crypto/hmac`, `crypto/elliptic`, or `crypto/ecdsa`, you need to add the missing package export data.

### Steps to add a package

1. **Generate the package export data file** (`.o` file):

```go
//go:build ignore

package main

import (
    "fmt"
    "go/importer"
    "go/token"
    "os"
    "golang.org/x/tools/go/gcexportdata"
)

func main() {
    fset := token.NewFileSet()
    imp := importer.ForCompiler(fset, "gc", nil)
    pkg, err := imp.Import("crypto/hmac")  // <-- target package
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error importing package: %v\n", err)
        os.Exit(1)
    }
    file, err := os.Create("packages/crypto_hmac.o")  // <-- output file
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error creating file: %v\n", err)
        os.Exit(1)
    }
    defer file.Close()
    // CRITICAL: Pass nil for fset, NOT the fset used for import
    if err := gcexportdata.Write(file, nil, pkg); err != nil {
        fmt.Fprintf(os.Stderr, "Error writing export data: %v\n", err)
        os.Exit(1)
    }
    fmt.Printf("Successfully created package export data for %s\n", pkg.Path())
}
```

Run with `go run gen_package.go`, then delete the script.

> **CRITICAL**: The `gcexportdata.Write` call must pass `nil` for the `fset` parameter. Passing the same fset used for import will embed absolute file paths, causing runtime errors.

2. **Check for dependencies**: Some packages depend on types from other packages. Common dependencies:

| Package | May require |
|---------|-------------|
| `crypto/hmac` | `hash` |
| `crypto/cipher` | `io` |
| `crypto/*` (most) | `io`, `hash` |

3. **Add mapping entry** to `mapping_generated.go` in alphabetical order:

```go
"crypto/hmac": "crypto_hmac.o",
```

4. **Rebuild the binary**: `./make.sh build`

### File naming convention

| Package Path | Export Data File |
|--------------|------------------|
| `crypto/hmac` | `crypto_hmac.o` |
| `crypto/elliptic` | `crypto_elliptic.o` |
| `golang.org/x/crypto/bcrypt` | `x_crypto_bcrypt.o` |

</details>

## Help and troubleshooting

If you encounter difficulties or unexpected results while installing the plugin with SonarQube, or when trying to scan a repository, please check out our guide [*Testing your configuration and troubleshooting*](docs/TROUBLESHOOTING.md) to run our plugin with step-by-step instructions.

To measure the plugin's runtime performance and heap usage — including a full end-to-end scan of a large project (Keycloak) — see [*Performance & Heap Testing*](docs/PERFORMANCE_TESTING.md).

## Contribution Guidelines

If you'd like to contribute to Sonar Cryptography Plugin, please take a look at our
[contribution guidelines](CONTRIBUTING.md). By participating, you are expected to uphold our [code of conduct](CODE_OF_CONDUCT.md).

We use [GitHub issues](https://github.com/cbomkit/sonar-cryptography/issues) for tracking requests and bugs. For questions
start a discussion using [GitHub Discussions](https://github.com/cbomkit/sonar-cryptography/discussions).

## License

The independently authored code in this repository is licensed under the
[Apache License 2.0](LICENSE.txt). The packaged plugin also contains third-party
code under its own licences, including sonar-java, sonar-python and sonar-go
under the [Sonar Source-Available License v1.0](https://www.sonarsource.com/license/ssal-1-0-0/),
subject to their individual-file licence notices.

The plugin JAR includes `META-INF/THIRD-PARTY-NOTICES.txt`, the SSAL text, and
each resolved analyser module's original legal files under
`META-INF/third-party/analyzers/`. Matching upstream Maven source JARs are included
under `META-INF/third-party/analyzer-sources/`, including the Java and Python
frontends. A pinned complete sonar-go release source ZIP in the same directory
also provides the native Go bridge, shaded Go modules and build scripts. Its
public commit maps to the plugin's build revision through `GitOrigin-RevId`.
The notices describe the versions, source locations and packaging transformations.

These packaging materials do not establish that every use is permitted by SSAL.
The permitted-purpose restrictions and the provenance and licence notices of
any adapted implementation code still require review before release.
