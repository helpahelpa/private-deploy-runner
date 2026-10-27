Provision the private, reviewed client packaging snapshot in ignored `local/trusted-tooling/client-build/` before building. `UPSTREAM.json` records the original script hashes and source commit. The game repository's Python scripts, project files, and build hooks are never imported or executed on the host. Update this snapshot through private review when packaging logic changes.

The host entrypoint is:

```sh
python3 scripts/build_client.py --config local/client-build.private.json \
  --source /operator/source --commit <40-character-commit> \
  --output local/releases/<new-release> --version 4.2.0.<allocated-counter>
```

The operator reserves a globally monotonic counter under the deployment lock; the builder requires a new output directory and a version of at least 62. APK files are published atomically with `manifest.json` and `client-tests.json`. No deployment, ADB, save, preferences, or network write happens here. Assets contain the new incremental pack, update configuration and server list; the deployment layer supplies the retained static asset base.

The private JSON configuration has these fields:

- `image`: an existing immutable Docker image ID, `sha256:…`. The image needs compatible Linux Python, OpenSSL, cryptography, dnfile, dncil and Pillow. The retained AST checks use a provisioned PowerShell toolchain; its parser and pure helper assertions execute inside the same restrictions. Build/test never pulls images or installs packages.
- `toolchains`: read-only `path` and `target` objects. Allowed targets are `/toolchain/jdk`, `/toolchain/dotnet`, `/toolchain/android`, and `/toolchain/pwsh`. Supply dedicated toolchain directories containing no secrets.
- `python_dependencies`: the container path for baked Python packages (defaults to `/python-deps`).
- `toolchain_files`: named `{path, sha256}` pins for the explicit compiler/DEX tools.
- `compile`: container paths `java`, `javac`, `android`, `r8`, `dotnet`, and `csc`. Optional `test_runtime` and `test_tfm` select the provisioned Linux CLR. `minimum_client_tests` and `required_test_ids` retain the reviewed baseline suite.
- `inputs`: named `{path, sha256}` objects for `base_apk`, `client_source`, `template`, `ca`, `key`, `cert`, `helper`, `helper_manifest`, `android_receipt`, `mscorlib.dll`, `System.dll`, `UnityEngine.dll`, and `LitJson.dll`. These are operator-owned, immutable local inputs. The signer must already exist. A matching established managed helper is preserved exactly; changed C# gets a newly compiled helper.
- `connection`: the original builder's endpoint-only configuration (`gameplay_transport`, optional secure `gameplay_url`, and `assets_origin`). Credentials and gameplay proxy settings are rejected; per-install routing remains external to the APK. Omitting the configuration builds the default TLS flavor.
- `fixtures`: relative destination names mapped to pinned private files. They are copied to the isolated source snapshot. `compile.test_fixture_destinations` optionally copies selected relative fixture names into the sandbox's temporary `/mnt/c` for retained test infrastructure.
- `test_commands`: argument arrays, normally `[["python3", "/trusted/regression.py"]]`. Every test container has network disabled, a read-only root and source, no capabilities, no signing identity, and no Docker socket. The trusted harness requires zero skips/errors/failures, retained test IDs, and a real full-suite result. Existing Windows transport fixtures are adapted to compile and execute the exact current C# probes on the provisioned Linux CLR. PowerShell AST checks use real PowerShell with bounded Windows lexical Path operations; packaging scratch uses `/work` while source remains immutable; the receipt identifies this platform explicitly.
- `forbidden_apk_strings`: private values which must be absent from every decompressed APK ZIP entry. Populate this with any actual gameplay proxy hostname/URI, proxy password and access credentials that must never ship. Values never enter build output or logs.

All private configurations, input locations, endpoint values, diagnostics and artifacts belong under ignored `local/`. Only Java and C# production blobs from the exact requested Git commit enter the compiler. Git LFS pointers resolve only to local object bytes matching their committed SHA256 and size, using the checkout’s canonical `.git/lfs/objects` or the operator’s explicit `lfs_object_store`; filters never execute. The receipt hashes all source and fixture data before and after testing. Java annotation processing is disabled; C# is passed directly to the compiler without MSBuild, project evaluation, generators or package restore. Newly compiled application code runs only in the restricted test containers. Signing happens afterward in the trusted host packager.
