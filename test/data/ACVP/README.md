# NIST ACVP sample corpora

These files are copied without modification from:

- Repository: <https://github.com/usnistgov/ACVP-Server>
- Commit: `975de31eb83d87039ec88934fdc47d8c312b892d`
- Commit date: 2026-08-12
- Release: `RELEASE/v1.1.0.43`
- Upstream path: `gen-val/json-files/`

Only `prompt.json` and `expectedResults.json` are checked in.
`internalProjection.json`, `registration.json`, and `validation.json`
are not required by the repo-local integrity test.

The SLH-DSA corpus in `test/data/SLHDSA/` is a different pin
(`15c0f3deeefbfa8cb6cd32a99e1ca3b738c66bf0`, `RELEASE/v1.1.0.42`).
It is not replaced by this directory. The ML-KEM and ML-DSA `.rsp`
files are also unchanged.

`isSample` is recorded as NIST shipped it. Several of these files
have `isSample` set to false. This directory does not rewrite that field.

## Coverage

| Directory | Groups | Cases | `isSample` |
| --------- | -----: | ----: | ---------- |
| `cSHAKE-128-1.0` | 2 | 101 | true |
| `cSHAKE-256-1.0` | 2 | 101 | true |
| `KMAC-128-1.0` | 8 | 800 | false |
| `KMAC-256-1.0` | 8 | 800 | false |
| `TupleHash-128-1.0` | 4 | 202 | true |
| `TupleHash-256-1.0` | 4 | 202 | true |
| `ParallelHash-128-1.0` | 4 | 202 | true |
| `ParallelHash-256-1.0` | 4 | 202 | true |
| `ML-KEM-keyGen-FIPS203` | 3 | 75 | false |
| `ML-KEM-encapDecap-FIPS203` | 12 | 165 | true |
| `ML-DSA-keyGen-FIPS204` | 3 | 75 | false |
| `ML-DSA-sigGen-FIPS204` | 24 | 360 | false |
| `ML-DSA-sigVer-FIPS204` | 12 | 180 | false |
| **Total** | **90** | **3465** | |

## Integrity

| File | Bytes | SHA-256 |
| ---- | ----: | ------- |
| `cSHAKE-128-1.0/prompt.json` | 28591 | `602505b60b9ddeae518887f925c527947af1712a12c37cfc6a4d014a36f78e03` |
| `cSHAKE-128-1.0/expectedResults.json` | 19700 | `be71953163ecfae0519ac84bc1851b4f474dd1cff2b587c0bde7c98fae2f5405` |
| `cSHAKE-256-1.0/prompt.json` | 48053 | `cf49b691b462032bff9c517f17981b3ec1f8eb5d70872cc5c14182930b4bab34` |
| `cSHAKE-256-1.0/expectedResults.json` | 18972 | `decd4148c906a9a8b4084f7c1f1a06f27330535ebb7a7f13282c95a4134c35e1` |
| `KMAC-128-1.0/prompt.json` | 4249938 | `d7e4edd54d534c51a162eae940213a3d47cf58ad61a1db6b080b03c482273d33` |
| `KMAC-128-1.0/expectedResults.json` | 268082 | `06e1be237f92995054c475c35b5b11c5637df699563997154c17e4b92f7696bd` |
| `KMAC-256-1.0/prompt.json` | 4264891 | `5b4b3c21edac5aae5a52dffe49ddba5576e90fb584c0e23fdedda5e51ec11548` |
| `KMAC-256-1.0/expectedResults.json` | 270311 | `7a54cc6e3899453156acbd73887262d5b1adb97939eba68ede3d44876da87881` |
| `TupleHash-128-1.0/prompt.json` | 183967 | `a8f4d53d02a17eccca75a04123a65d129fdf84ea4c25552cd5ceac456f021dfe` |
| `TupleHash-128-1.0/expectedResults.json` | 38218 | `c50486f527888605973d747f59399a14562d11c2513a377510a9791ace459a86` |
| `TupleHash-256-1.0/prompt.json` | 207776 | `64ff03ca1e8465c7e6538bd905d9fedb12b391a9bb2a54b8e6db79ed5d1ddd1d` |
| `TupleHash-256-1.0/expectedResults.json` | 38164 | `6fb188e85333ec3a2e292b8c521a0b9b793c6e27b126710adfd6121ccb26c5b1` |
| `ParallelHash-128-1.0/prompt.json` | 878240 | `9e65ae062d1ab03d9a349c060d0088d517308cd3859ad180b50f0e86639d2a03` |
| `ParallelHash-128-1.0/expectedResults.json` | 38534 | `7587f20c11b4f3287fb875d19b804e39561c11a480e9ce2932d30410987125ee` |
| `ParallelHash-256-1.0/prompt.json` | 934004 | `4b3d70f60ea62fe575e64fd85bdcc9dbe2b3d811eb9fd93fc9a511b3f304015d` |
| `ParallelHash-256-1.0/expectedResults.json` | 38310 | `fa30a42f67143f275c45e4b4ea541e6bab5975727a0857192f40a8948cb56bc6` |
| `ML-KEM-keyGen-FIPS203/prompt.json` | 16066 | `3f9ce34f6c836c77958bad2729e837c3b213f44ac36c3065976e7acca6389523` |
| `ML-KEM-keyGen-FIPS203/expectedResults.json` | 544032 | `a253d0ad91c95ebea5b409673defef0aa49d65d4ed72286399e2e798ddf073a4` |
| `ML-KEM-encapDecap-FIPS203/prompt.json` | 624189 | `998e22dfb12efb14ce9fdff911ca634b13612819a1806f25da69adba7e16db91` |
| `ML-KEM-encapDecap-FIPS203/expectedResults.json` | 190940 | `9089ec6ff2424da9f2782b89b2f831a329a3e28d6e5e24b802b78ff36ac61cdf` |
| `ML-DSA-keyGen-FIPS204/prompt.json` | 10062 | `43e81ad820e495dbcad086fe27c1008393a8c32100bbbff77c558c3f06dcefef` |
| `ML-DSA-keyGen-FIPS204/expectedResults.json` | 873632 | `361f47ca19d592adcc66ff2cb591686ad785fea157b295648738bed6921a68df` |
| `ML-DSA-sigGen-FIPS204/prompt.json` | 5044293 | `447749d72817b211160d243311ce32302f3023e59c355b0f70be2bd3e9e7830d` |
| `ML-DSA-sigGen-FIPS204/expectedResults.json` | 2511972 | `228d011bbe274aeb93e22eea1e0d57b78f43795cf6a64fb5ef1e626485a0bedb` |
| `ML-DSA-sigVer-FIPS204/prompt.json` | 3125947 | `e2cba4589389756fa0bea1a7e6837138bf0a81f9d14234c9ee8f6d33caa1654e` |
| `ML-DSA-sigVer-FIPS204/expectedResults.json` | 13956 | `e1d84ef1b2f35196278ab0b0ed6a46ec62cc03d2dfa92c564199e1999bfb8ea6` |

```bash
dart test test/acvp_corpus_test.dart
```

This test checks file bytes and that prompt cases pair with
expected results by `tgId` and `tcId`. It does not execute the algorithms.

## NIST Notice


NIST-developed software is provided by NIST as a public service. You may use,
copy, and distribute copies of the software in any medium, provided that you
keep intact this entire notice. You may improve, modify, and create derivative
works of the software or any portion of the software, and you may copy and
distribute such modifications or works. Modified works should carry a notice
stating that you changed the software and should note the date and nature of
any such change. Please explicitly acknowledge the National Institute of
Standards and Technology as the source of the software.

NIST-developed software is expressly provided "AS IS." NIST MAKES NO WARRANTY
OF ANY KIND, EXPRESS, IMPLIED, IN FACT, OR ARISING BY OPERATION OF LAW,
INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTY OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE, NON-INFRINGEMENT, AND DATA ACCURACY. NIST
NEITHER REPRESENTS NOR WARRANTS THAT THE OPERATION OF THE SOFTWARE WILL BE
UNINTERRUPTED OR ERROR-FREE, OR THAT ANY DEFECTS WILL BE CORRECTED. NIST DOES
NOT WARRANT OR MAKE ANY REPRESENTATIONS REGARDING THE USE OF THE SOFTWARE OR
THE RESULTS THEREOF, INCLUDING BUT NOT LIMITED TO THE CORRECTNESS, ACCURACY,
RELIABILITY, OR USEFULNESS OF THE SOFTWARE.

You are solely responsible for determining the appropriateness of using and
distributing the software and you assume all risks associated with its use,
including but not limited to the risks and costs of program errors, compliance
with applicable laws, damage to or loss of data, programs or equipment, and
the unavailability or interruption of operation. This software is not intended
to be used in any situation where a failure could cause risk of injury or
damage to property. The software developed by NIST employees is not subject to
copyright protection within the United States.
