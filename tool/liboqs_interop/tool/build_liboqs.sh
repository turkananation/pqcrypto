#!/usr/bin/env bash
set -euo pipefail

version="${LIBOQS_VERSION:-0.15.0}"
commit="${LIBOQS_COMMIT:-97f6b86b1b6d109cfd43cf276ae39c2e776aed80}"
jobs="${NATIVE_BUILD_JOBS:-4}"
prefix="${LIBOQS_PREFIX:-$(pwd)/.native/liboqs-${version}}"
work_dir="${NATIVE_BUILD_DIR:-/tmp/pqcrypto-liboqs-${version}}"
source_dir="${work_dir}/src"
build_dir="${work_dir}/build"
minimal_algorithms="$(
  printf '%s' \
    'KEM_ml_kem_512;KEM_ml_kem_768;KEM_ml_kem_1024;' \
    'SIG_ml_dsa_44;SIG_ml_dsa_65;SIG_ml_dsa_87;' \
    'SIG_slh_dsa_pure_sha2_128s;SIG_slh_dsa_pure_sha2_128f;' \
    'SIG_slh_dsa_pure_sha2_192s;SIG_slh_dsa_pure_sha2_192f;' \
    'SIG_slh_dsa_pure_sha2_256s;SIG_slh_dsa_pure_sha2_256f;' \
    'SIG_slh_dsa_pure_shake_128s;SIG_slh_dsa_pure_shake_128f;' \
    'SIG_slh_dsa_pure_shake_192s;SIG_slh_dsa_pure_shake_192f;' \
    'SIG_slh_dsa_pure_shake_256s;SIG_slh_dsa_pure_shake_256f'
)"

if [[ -f "${prefix}/lib/liboqs.so" || -f "${prefix}/lib64/liboqs.so" ]]; then
  printf 'liboqs %s already installed at %s\n' "${version}" "${prefix}"
  exit 0
fi

rm -rf "${work_dir}" "${prefix}"
mkdir -p "${source_dir}"

git -C "${source_dir}" init
git -C "${source_dir}" remote add origin \
  https://github.com/open-quantum-safe/liboqs.git
git -C "${source_dir}" fetch --depth 1 origin "${commit}"
git -C "${source_dir}" checkout --detach FETCH_HEAD
test "$(git -C "${source_dir}" rev-parse HEAD)" = "${commit}"

cmake -S "${source_dir}" -B "${build_dir}" -GNinja \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INSTALL_PREFIX="${prefix}" \
  -DCMAKE_INSTALL_LIBDIR=lib \
  -DBUILD_SHARED_LIBS=ON \
  -DOQS_BUILD_ONLY_LIB=ON \
  -DOQS_USE_OPENSSL=OFF \
  -DOQS_MINIMAL_BUILD="${minimal_algorithms}"
cmake --build "${build_dir}" --parallel "${jobs}"
cmake --install "${build_dir}"

printf 'liboqs %s (%s) installed at %s\n' \
  "${version}" "${commit}" "${prefix}"
