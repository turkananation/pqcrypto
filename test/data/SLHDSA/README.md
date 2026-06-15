# NIST ACVP SLH-DSA Sample Corpus

This directory contains the official NIST ACVP sample vectors for FIPS 205
SLH-DSA. The files are copied without modification from:

- Repository: <https://github.com/usnistgov/ACVP-Server>
- Commit: `15c0f3deeefbfa8cb6cd32a99e1ca3b738c66bf0`
- Commit date: 2026-04-16
- Release commit: `RELEASE/v1.1.0.42`
- Upstream path: `gen-val/json-files/SLH-DSA-*-FIPS205/`

Only `prompt.json` and `expectedResults.json` are checked in. These are the
questions presented to an implementation under test and the corresponding
sample answers. The upstream `internalProjection.json`, `registration.json`,
and `validation.json` files are not required by the repo-local runner.

## Coverage

| Operation | Test groups | Test cases | Parameter sets |
| --------- | ----------: | ---------: | -------------: |
| keyGen    |          12 |        120 |             12 |
| sigGen    |          72 |        624 |             12 |
| sigVer    |          36 |        504 |             12 |
| **Total** |     **120** |  **1,248** |         **12** |

The corpus covers all FIPS 205 parameter sets:

- SLH-DSA-SHA2-128s/128f/192s/192f/256s/256f
- SLH-DSA-SHAKE-128s/128f/192s/192f/256s/256f

The signature vectors cover the ACVP internal interface and the external pure
and pre-hash interfaces. Signature generation includes deterministic and
hedged groups. Signature verification includes both passing and failing cases.

The v0.4.0 release gate consumes the six SHAKE parameter sets. The six SHA-2
sets remain checked in now so the later v0.5.0 gate uses the same pinned corpus
revision.

## Integrity

| File                                          |      Bytes | SHA-256                                                            |
| --------------------------------------------- | ---------: | ------------------------------------------------------------------ |
| `SLH-DSA-keyGen-FIPS205/prompt.json`          |     32,454 | `bce170976f257ee3dfc8c54ea46722ccb553539847daa6d8048f0216cc28b51c` |
| `SLH-DSA-keyGen-FIPS205/expectedResults.json` |     45,192 | `f35f74b6676d6b369c87e88c36698f28c14d5929d31e507d910288c69258afee` |
| `SLH-DSA-sigGen-FIPS205/prompt.json`          |  5,512,830 | `afa673eacdf0aec53512a159159b7632684adfcd0d88f8640a7f6f5796aacdc8` |
| `SLH-DSA-sigGen-FIPS205/expectedResults.json` | 32,595,492 | `71e8e0f7e4b0cfd1747314299204d9d4d50968d200a4ae873921eaa7aabeaad1` |
| `SLH-DSA-sigVer-FIPS205/prompt.json`          | 30,513,796 | `4e7beb1233e47baa0acdd36417c66c45811aa40a4e32ffdb1a35d93b13b289fb` |
| `SLH-DSA-sigVer-FIPS205/expectedResults.json` |     39,216 | `259f5e2a0665de0adc0fefa45b5db3a2a6ed13c3c44d14bdaf64a80aee12c687` |

Run the corpus integrity and schema gate with:

```bash
dart test test/slhdsa_acvp_corpus_test.dart
```

The byte-exact implementation runner is `test/slhdsa_kat_test.dart`. It pairs
prompt and expected-result groups by `tgId` and cases by `tcId`, and executes
all 624 cases for the six SHAKE parameter sets. The SHA-2 groups remain pinned
for the later v0.5.0 implementation.

The runner accepts optional diagnostic filters:

```bash
SLHDSA_KAT_PARAMETER=SLH-DSA-SHAKE-128f \
SLHDSA_KAT_OPERATION=sigGen \
SLHDSA_KAT_LIMIT=1 \
dart test test/slhdsa_kat_test.dart
```

Do not substitute SPHINCS+ round-3, RFC 8391 XMSS, or SP 800-208 vectors for
this corpus. Those validate different algorithms or pre-FIPS behavior.

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
