# SPDX-License-Identifier: MIT
"""Tests for the ML-DSA keypair, sign and verify build options.

Each test configures and builds liboqs with only ML-DSA-44 in a throwaway
build directory, then checks that:

  * `oqsconfig.h` defines exactly the enabled operations,
  * the library exposes the wrapper of the enabled operations only,
  * the enabled operations work and the disabled ones fail cleanly through
    the generic `OQS_SIG_*` API.

The functional check runs the `test_ml_dsa_options` program, which is built
from `tests/test_ml_dsa_options.c` by the normal liboqs build. The verify-only
build checks a signature that the default build made, because its own keypair
and sign wrappers are compiled out.
"""

import os
import platform
import re
import shutil

import helpers
import pytest

LIBOQS_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

pytestmark = pytest.mark.skipif(
    platform.system() == "Windows" or shutil.which("cmake") is None or shutil.which("nm") is None,
    reason="requires cmake, nm and a GCC/Clang-style compiler driver",
)

OPS = ("KEYPAIR", "SIGN", "VERIFY")

# Public liboqs wrapper symbols. A disabled operation's wrapper is compiled out,
# so its symbol is absent from the library. The mldsa-native backend code stays
# in the archive and is dropped by the linker's dead-code elimination instead.
OQS_SYMBOLS = {
    "KEYPAIR": "OQS_SIG_ml_dsa_44_keypair",
    "SIGN": "OQS_SIG_ml_dsa_44_sign",
    "VERIFY": "OQS_SIG_ml_dsa_44_verify",
}

COMMON_ARGS = [
    "-GNinja" if shutil.which("ninja") else "-GUnix Makefiles",
    "-DOQS_USE_OPENSSL=OFF",
    "-DOQS_MINIMAL_BUILD=SIG_ml_dsa_44",
    "-DCMAKE_BUILD_TYPE=Release",
]

APP_TARGET = "test_ml_dsa_options"


def configure(build_dir, *args):
    helpers.run_subprocess(["cmake", "-S", LIBOQS_ROOT, "-B", str(build_dir), *COMMON_ARGS, *args])


def build(tmp_path, enabled):
    """Build liboqs and the test program with the given operations enabled."""
    build_dir = tmp_path / ("build_" + ("_".join(enabled) or "none"))
    args = ["-DOQS_ENABLE_SIG_ML_DSA_%s=%s" % (op, "ON" if op in enabled else "OFF") for op in OPS]
    configure(build_dir, *args)
    helpers.run_subprocess(["cmake", "--build", str(build_dir), "--target", APP_TARGET, "--parallel"])
    return build_dir


def app_path(build_dir):
    return str(build_dir / "tests" / APP_TARGET)


def defined_symbols(build_dir):
    output = helpers.run_subprocess(["nm", "-g", str(build_dir / "lib" / "liboqs.a")])
    # Defined text symbols only, with the leading underscore of Mach-O removed.
    return {m.group(1) for m in re.finditer(r"^[0-9a-fA-F]+ T _?(\S+)$", output, re.MULTILINE)}


@pytest.fixture(scope="module")
def reference(tmp_path_factory):
    """A key pair and a signature made by a build that has all operations."""
    tmp_path = tmp_path_factory.mktemp("ml_dsa_reference")
    build_dir = build(tmp_path, OPS)
    files = [tmp_path / name for name in ("pk.bin", "sk.bin", "sig.bin")]
    helpers.run_subprocess([app_path(build_dir), "gen", *map(str, files)])
    return files


def test_options_on_by_default(tmp_path):
    """Without explicit settings, all three operations stay enabled in a minimal build."""
    build_dir = tmp_path / "build_default"
    configure(build_dir)
    with open(str(build_dir / "CMakeCache.txt")) as f:
        cache = f.read()
    config = (build_dir / "include" / "oqs" / "oqsconfig.h").read_text()
    for op in OPS:
        assert "OQS_ENABLE_SIG_ML_DSA_%s:BOOL=ON" % op in cache
        assert "#define OQS_ENABLE_SIG_ML_DSA_%s 1" % op in config


@pytest.mark.parametrize("enabled", [
    ("KEYPAIR", "SIGN", "VERIFY"),
    ("SIGN", "VERIFY"),
    ("KEYPAIR", "VERIFY"),
    ("KEYPAIR", "SIGN"),
    ("VERIFY",),
], ids=lambda e: "+".join(e))
def test_ml_dsa_operations(tmp_path, reference, enabled):
    build_dir = build(tmp_path, enabled)

    config = (build_dir / "include" / "oqs" / "oqsconfig.h").read_text()
    symbols = defined_symbols(build_dir)
    for op in OPS:
        on = op in enabled
        assert ("#define OQS_ENABLE_SIG_ML_DSA_%s 1" % op in config) == on, op
        assert (OQS_SYMBOLS[op] in symbols) == on, OQS_SYMBOLS[op]

    helpers.run_subprocess([app_path(build_dir), "run", *map(str, reference)])
