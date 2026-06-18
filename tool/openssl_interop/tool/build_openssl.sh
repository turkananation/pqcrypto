#!/usr/bin/env bash
set -euo pipefail

version="${OPENSSL_VERSION:-4.0.1}"
sha256="${OPENSSL_SHA256:-2db3f3a0d6ea4b59e1f094ace2c8cd536dffb87cdc39084c5afa1e6f7f37dd09}"
jobs="${NATIVE_BUILD_JOBS:-4}"
prefix="${OPENSSL_PREFIX:-$(pwd)/.native/openssl-${version}}"
work_dir="${NATIVE_BUILD_DIR:-/tmp/pqcrypto-openssl-${version}}"
archive="${work_dir}/openssl-${version}.tar.gz"
source_dir="${work_dir}/src"

if [[ -x "${prefix}/bin/openssl" ]]; then
  LD_LIBRARY_PATH="${prefix}/lib${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}" \
    "${prefix}/bin/openssl" version
  exit 0
fi

rm -rf "${work_dir}" "${prefix}"
mkdir -p "${work_dir}" "${source_dir}"

curl -fL \
  "https://github.com/openssl/openssl/releases/download/openssl-${version}/openssl-${version}.tar.gz" \
  -o "${archive}"
printf '%s  %s\n' "${sha256}" "${archive}" | sha256sum -c -
tar xzf "${archive}" -C "${source_dir}" --strip-components=1

(
  cd "${source_dir}"
  ./Configure no-docs no-tests shared \
    --prefix="${prefix}" \
    --libdir=lib
  make -j"${jobs}"
  make install_sw
)

LD_LIBRARY_PATH="${prefix}/lib${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}" \
  "${prefix}/bin/openssl" version
