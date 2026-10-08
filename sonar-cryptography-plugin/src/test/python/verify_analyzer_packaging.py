"""Verify the legal materials and source distributions in the shaded release JAR."""

import argparse
from pathlib import Path
import xml.etree.ElementTree as ET
from zipfile import ZipFile


def verify(plugin_jar, repository):
    root = Path(__file__).resolve().parents[4]
    namespace = {"m": "http://maven.apache.org/POM/4.0.0"}
    properties = ET.parse(root / "pom.xml").find("m:properties", namespace)
    with ZipFile(plugin_jar) as packaged:
        names = packaged.namelist()
        assert len(names) == len(set(names)), "Duplicate JAR entries"
        notice = packaged.read("META-INF/THIRD-PARTY-NOTICES.txt").decode()
        assert "${" not in notice, "Unresolved Maven properties in notices"
        assert packaged.read("META-INF/LICENSE.txt") == (root / "LICENSE.txt").read_bytes()
        java_license = (
            root / "sonar-cryptography-plugin/src/main/resources"
            / "META-INF/third-party/SSALv1.txt"
        )
        assert packaged.read("META-INF/third-party/SSALv1.txt") == java_license.read_bytes()

        for language in ("java", "python", "go"):
            version = properties.find("m:sonar." + language + ".version", namespace).text
            artifact = "sonar-" + language + "-plugin"
            coordinate = "org.sonarsource." + language + ":" + artifact + ":" + version
            assert coordinate in notice, "Missing resolved coordinate: " + coordinate
            source_name = artifact + "-" + version + "-sources.jar"
            assert source_name in notice, "Missing matching source URL: " + source_name
            artifact_directory = (
                repository / "org/sonarsource" / language / artifact / version
            )
            binary = artifact_directory / (artifact + "-" + version + ".jar")
            prefix = "META-INF/third-party/analyzers/" + artifact + "-" + version + "-jar/"
            assert prefix in notice, "Incorrect legal-file directory: " + prefix
            with ZipFile(binary) as original:
                legal_files = [
                    name
                    for name in original.namelist()
                    if not name.endswith("/") and (
                        "license" in name.lower()
                        or "notice" in name.lower()
                        or name.startswith("about_files/")
                    )
                ]
                assert legal_files, "No upstream legal files found: " + artifact
                for name in legal_files:
                    assert packaged.read(prefix + name) == original.read(name), (
                        "Missing or changed legal file: " + prefix + name
                    )
            # Check the published source archives, not just their filenames.
            sources = artifact_directory / source_name
            assert packaged.read(
                "META-INF/third-party/analyzer-sources/" + source_name
            ) == sources.read_bytes()

        # These implementations are absent from the plugin-only source JARs.
        for language in ("java", "python"):
            version = properties.find("m:sonar." + language + ".version", namespace).text
            source_name = language + "-frontend-" + version + "-sources.jar"
            assert "META-INF/third-party/analyzer-sources/" + source_name in names, (
                "Missing parser implementation sources: " + source_name
            )
        assert "does not include the native Go-to-Slang" in notice, (
            "Missing upstream source gap"
        )
    print(
        "Verified analyzer notices, licences and published source JARs in "
        + str(plugin_jar)
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("plugin_jar", type=Path)
    parser.add_argument("--repository", type=Path, default=Path.home() / ".m2/repository")
    arguments = parser.parse_args()
    verify(arguments.plugin_jar, arguments.repository)
