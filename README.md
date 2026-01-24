# Sonar Cryptography Plugin (CBOMkit-hyperion)

[![License](https://img.shields.io/github/license/cbomkit/sonar-cryptography.svg?)](https://opensource.org/licenses/Apache-2.0) <!--- long-description-skip-begin -->
[![Current Release](https://img.shields.io/github/release/cbomkit/sonar-cryptography.svg?logo=IBM)](https://github.com/cbomkit/sonar-cryptography/releases)


This repository contains a SonarQube Plugin that detects cryptographic assets 
in source code and generates [CBOM](https://cyclonedx.org/capabilities/cbom/).
It is part of **the [CBOMKit](https://github.com/cbomkit) toolset**.

## Version compatibility

| Plugin Version  | SonarQube Version              |
|-----------------|--------------------------------|
| 1.3.7 and up    | SonarQube 9.9 (LTS) and up     |
| 1.3.2 and 1.3.6 | SonarQube 9.8 (LTS) up to 10.8 | 
| 1.2.0 to 1.3.1  | SonarQube 9.8 (LTS) up to 10.4 |      


## Supported languages and libraries

| Language | Cryptographic Library                                                                         | Coverage |
|----------|-----------------------------------------------------------------------------------------------|----------|
| Java     | [JCA](https://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html) | 100%     |
|          | [BouncyCastle](https://github.com/bcgit/bc-java) (*light-weight API*)                         | 100%[^1] |
| Python   | [pyca/cryptography](https://cryptography.io/en/latest/)                                       | 100%     |
| Go       | [crypto](https://pkg.go.dev/crypto) (*standard library*)                                      | 100%[^2] |
|          | [golang.org/x/crypto](https://pkg.go.dev/golang.org/x/crypto)                                 | Partial[^3] |


[^1]: We only cover the BouncyCastle *light-weight API* according to [this specification](https://javadoc.io/static/org.bouncycastle/bctls-jdk14/1.80/specifications.html)
[^2]: All packages under [`crypto`](https://pkg.go.dev/crypto@go1.25.6#section-directories) are covered except `crypto/x509`
[^3]: Covers `golang.org/x/crypto/hkdf`, `golang.org/x/crypto/pbkdf2`, and `golang.org/x/crypto/sha3`

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

The plugin provides new inventory rules (Cbomkit Cryptography Repository) regarding the use of cryptography for 
the supported languages.
If you enable these rules, a source code scan creates a cryptographic inventory by creating a 
[CBOM](https://cyclonedx.org/capabilities/cbom/) with all cryptographic assets and writing 
a `cbom.json` to the scan directory.

### Add Cryptography Rules to your Quality Profile

This plugin incorporates rules specifically focused on cryptography.

> To generate a Cryptography Bill of Materials (CBOM), it is mandatory to activate at 
> least one of these cryptography-related rules.

![Activate Rules Crypto Rules](docs/images/rules.png)

As of the current version, the plugin contains one single rule for creating a cryptographic inventory. 
Future updates may introduce additional rules to expand functionality.

### Scan Source Code

Now you can follow the [SonarQube documentation](https://docs.sonarqube.org/latest/analyzing-source-code/overview/) 
to start your first scan.

### Visualizing your CBOM

Once you have scanned your source code with the plugin, and obtained a `cbom.json` file, you can use [Cbomkit's CBOM Viewer](https://github.com/cbomkit/cbomkit) service to know more about it.
It provides you with general insights about the cryptography used in your source code and its compliance with post-quantum safety.
It also allows you to explore precisely each cryptography asset and its detailed specification, and displays where it appears in your code.

## Build

### Adding packages to sonar-go-to-slang

Go cryptographic detection relies on [sonar-go-to-slang](https://github.com/SonarSource/sonar-go/tree/master/sonar-go-to-slang) for type resolution. The default binary includes common packages, but some cryptographic packages may require you to rebuild it with additional package export data.

#### When is this needed?

If you see "undefined: \<identifier\>" errors during type checking for packages like `crypto/hmac`, `crypto/elliptic`, or `crypto/ecdsa`, you need to add the missing package export data.

#### Steps to add a package

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

#### File naming convention

| Package Path | Export Data File |
|--------------|------------------|
| `crypto/hmac` | `crypto_hmac.o` |
| `crypto/elliptic` | `crypto_elliptic.o` |
| `golang.org/x/crypto/bcrypt` | `x_crypto_bcrypt.o` |

## Help and troubleshooting

If you encounter difficulties or unexpected results while installing the plugin with SonarQube, or when trying to scan a repository, please check out our guide [*Testing your configuration and troubleshooting*](docs/TROUBLESHOOTING.md) to run our plugin with step-by-step instructions.

## Contribution Guidelines

If you'd like to contribute to Sonar Cryptography Plugin, please take a look at our
[contribution guidelines](CONTRIBUTING.md). By participating, you are expected to uphold our [code of conduct](CODE_OF_CONDUCT.md).

We use [GitHub issues](https://github.com/cbomkit/sonar-cryptography/issues) for tracking requests and bugs. For questions
start a discussion using [GitHub Discussions](https://github.com/cbomkit/sonar-cryptography/discussions).

## License

[Apache License 2.0](LICENSE.txt)









