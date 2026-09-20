# Android KeyDescription reference fixtures

The Base64 files contain only the DER value of extension
`1.3.6.1.4.1.11129.2.1.17` extracted from the first certificate in Google's
published test chains. They exercise parsing; they are not trusted certificates,
fresh challenges, acceptable application identities or device acceptance
evidence.

Source: [android/keyattestation](https://github.com/android/keyattestation),
commit `bc8737c33470dcba53042512e0290ae9e059e086`.

| Fixture                           | Original path under `testdata/`  |
| --------------------------------- | -------------------------------- |
| `akita-key-description.base64`    | `akita/sdk34/TEE_EC_NONE.pem`    |
| `frankel-key-description.base64`  | `frankel/sdk37/TEE_EC_2026.pem`  |
| `blueline-key-description.base64` | `blueline/sdk28/SB_RSA_NONE.pem` |
| `akita-chain.pem`                 | `akita/sdk34/TEE_EC_NONE.pem`    |
| `frankel-chain.pem`               | `frankel/sdk37/TEE_EC_2026.pem`  |
| `blueline-chain.pem`              | `blueline/sdk28/TEE_EC_NONE.pem` |

`reference-roots.json` is the repository's top-level `roots.json` at that
commit. Certificate-path tests use those roots independently of the presented
chains, fixed validation dates and an explicitly synthetic empty revocation
snapshot. They prove signature/path processing of the reference chains, not
current revocation status or acceptance of their key properties for our
application. Production root and revocation updates must not use these test
fixtures.

`key-description.fixture.ts` generates synthetic DER for negative and
signed-chain tests. Test helpers and fixture data are excluded from the package
compilation.

The upstream repository is Copyright Google LLC and licensed under Apache 2.0;
see the accompanying `LICENSE.android-keyattestation` file. No implementation
source was copied into the parser or policy verifier.
