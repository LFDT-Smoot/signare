# HTTP-infra OpenAPI generator

Generates the HTTP infrastructure code under `app/pkg/infra/generated` from the OpenAPI spec
(`app/docs/open-api-specs/signare-api`) using a custom OpenAPI Generator plugin (`signare-plugin/`).

The generated code **is committed**, so normal builds, tests and CI do **not** run the generator.
You only need to regenerate when the OpenAPI spec or the `signare-plugin` changes.

## Regenerate

From the repo root:

```bash
make -C app tools.generate          # bundle + lint the spec, then regenerate + format
```

or directly in this directory:

```bash
make                                # build_signare_plugin + generate + format
```

## How the generator binary is obtained

The `openapi-generator-cli` jar is **not committed** (it is a ~30 MB binary blob). Instead it is
fetched on demand and integrity-checked:

- The version is pinned in `signare-plugin/pom.xml` (`openapi-generator-version`, currently `7.9.0`).
- `make fetch_openapi_generator` downloads `openapi-generator-cli-<version>.jar` from Maven Central
  into the gitignored `.cache/` directory and verifies it against the pinned SHA-256 in
  `openapi-generator-cli-<version>.jar.sha256` before any use. The codegen targets depend on this,
  so a tampered or wrong-version jar fails the build before it can generate code.

## Bumping the generator version

1. Update `openapi-generator-version` in `signare-plugin/pom.xml`.
2. Download the new jar, compute its SHA-256, and commit it as
   `openapi-generator-cli-<new-version>.jar.sha256` (remove the old one).
   Maven Central provenance: the jar's published SHA-1 is listed next to the artifact on
   `repo1.maven.org` (for 7.9.0: `369eafe4a877ad496504c3fd0eebfd3586666d16`).
3. Regenerate and review the resulting diff under `app/pkg/infra/generated` on its own — a generator
   bump can change the emitted Go, so keep it separate from unrelated changes.
