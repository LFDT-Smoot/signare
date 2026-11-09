# Releasing

This guide describes how changes are released from `develop` to `main`, how releases are versioned and tagged, how a candidate is tested as a pre-release, and how a released version is patched. The commands assume `upstream` is the remote for `LFDT-Smoot/signare`.

Signare follows [Gitflow](https://nvie.com/posts/a-successful-git-branching-model/) without release branches. Gitflow suits software that is explicitly versioned, and Signare is deployed, upgraded and migrated by version.

---

## Branching model

| Branch | Purpose |
|---|---|
| `develop` | Gitflow's integration branch. Every feature and fix pull request targets it. |
| `main` | Released code only. Every merge into it is a release or a hotfix, and carries a tag. |
| `hotfix/<name>` | A fix to a released version, branched from `main`. |

There are no release branches, and no branch name contains the word "release".

`main` accepts changes only through a pull request that passes the DCO check, so every commit needs a sign-off. Commit with `git commit -s`.

`develop` must never be deleted. GitHub deletes the source branch of every merged pull request in this repository, so `develop` needs a ruleset on `refs/heads/develop` with **Restrict deletions** enabled.

## Versioning

Versions follow [Semantic Versioning](https://semver.org/) and are recorded in [`CHANGELOG.md`](CHANGELOG.md) in the [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) format. Each release is tagged `vX.Y.Z`.

| Release contains | Version bump |
|---|---|
| Any changelog entry marked **Breaking** | Major (`X.0.0`) |
| New features, no breaking changes | Minor (`X.Y.0`) |
| Fixes only | Patch (`X.Y.Z`) |

A pre-release carries a hyphen suffix, such as `2.1.0-rc.1`, and sorts before the release it precedes.

## Release procedure

1. **Prepare the release.** On a branch from `develop` named `chore/X.Y.Z-stabilisation`, run the pre-release checks below with the Go version named in `app/go.mod`. Fix anything they find in its own commit, with its own changelog entry, for example a toolchain or dependency upgrade that clears a vulnerability. When the Go version moves, move it in all three `go.mod` files, the `run.go` setting in `.golangci.yaml` and the pinned build base image in `app/Dockerfile` together.

    | Check | Command | Expected |
    |---|---|---|
    | Lint and RBAC validation | `make -C app lint` and `make -C deployment lint` | 0 issues, all seven RBAC steps succeed |
    | Unit tests | `make -C app unit_test` | 0 failures |
    | Race detector | `make -C app race_test` | passes |
    | Vulnerabilities | `go run golang.org/x/vuln/cmd/govulncheck@latest ./...` in `app`, `deployment` and `app/tools/rbac-validator` | 0 reachable vulnerabilities |
    | Generated code | `make -C app tools.generate`, then `git status` | no changes |
    | Image | `make -C deployment ci.docker_build` | builds |

    The tests need SoftHSM 2 with a writable token store, and the linters must be built with a Go at least as new as `app/go.mod` names, see the [code standards](app/docs/mkdocs/docs/contribute/code-standards.md).

2. **Cut the changelog.** As the last commit on the same branch, insert `## [X.Y.Z] - YYYY-MM-DD` directly under `## [Unreleased]`, so every entry moves to the new version and `[Unreleased]` is left empty. Do not reword or drop entries. Commit it alone as `chore(release): X.Y.Z`. Open a pull request into `develop` and merge it with a merge commit.

    Once it merges, ask the authors of open pull requests that add a changelog entry to move it back under `[Unreleased]`. Otherwise git places it under the new release, because the headings it was written against now belong to that section.

3. **Check that the release merges cleanly.** The command exits 0 when there is no conflict. A conflict means something reached `main` outside this procedure, usually a hotfix that was not merged back into `develop`.

    ```bash
    git fetch upstream
    git merge-tree --write-tree upstream/main upstream/develop
    ```

4. **Open the release pull request** from `develop` into `main`, titled `Release vX.Y.Z`, listing the breaking changes and the evidence from step 1. Until `develop` has its ruleset, open it from a temporary copy instead, so GitHub deletes the copy on merge rather than `develop`.

    ```bash
    git fetch upstream
    git push upstream upstream/develop:refs/heads/chore/merge-develop-into-main
    ```

    Once approved, merge it with **Create a merge commit**. Never squash or rebase it. Either leaves `main` without the commits of `develop`, and the next release is then likely to conflict.

5. **Tag the release.** Create an annotated, signed tag on the merge commit on `main`.

    ```bash
    git fetch upstream
    git log -1 --oneline upstream/main   # must be the release merge commit
    git tag -s vX.Y.Z upstream/main -m "signare vX.Y.Z" -m "<one-paragraph summary>"
    git push upstream vX.Y.Z
    ```

6. **Publish the GitHub Release** from the tag, titled `vX.Y.Z`, with the changelog section as the release notes. The notes are read from the tag, not the working tree, and nothing is published if they come out empty. Escape the dots of the version in the `awk` pattern, for example `2\.0\.0`.

    ```bash
    git show vX.Y.Z:CHANGELOG.md | awk '/^## \[X\.Y\.Z\] /{f=1;next} /^## \[/{f=0} f' > /tmp/notes.md
    test -s /tmp/notes.md && gh release create vX.Y.Z --verify-tag --title "vX.Y.Z" --notes-file /tmp/notes.md
    ```

7. **Verify the release.** The first command prints the `develop` ref, and fails if `develop` was deleted. The two diffs print nothing, the second unless `develop` has moved on since the release.

    ```bash
    git fetch upstream
    git ls-remote --exit-code --heads upstream develop
    git diff vX.Y.Z upstream/main --stat
    git diff vX.Y.Z upstream/develop --stat
    ```

## Pre-releases

A pre-release lets a candidate be tested, for example by downstream integration tests, before the release pull request is opened.

1. **Prepare and cut the changelog** as in steps 1 and 2 of the release procedure, so the candidate carries the `[X.Y.Z]` section.

2. **Tag the candidate** on the tip of `develop`, numbering from `rc.1`.

    ```bash
    git fetch upstream
    git tag -s vX.Y.Z-rc.N upstream/develop -m "signare vX.Y.Z-rc.N"
    git push upstream vX.Y.Z-rc.N
    ```

3. **Publish it as a pre-release**, with the notes of the coming release.

    ```bash
    git show vX.Y.Z-rc.N:CHANGELOG.md | awk '/^## \[X\.Y\.Z\] /{f=1;next} /^## \[/{f=0} f' > /tmp/notes.md
    test -s /tmp/notes.md && gh release create vX.Y.Z-rc.N --verify-tag --prerelease --title "vX.Y.Z-rc.N" --notes-file /tmp/notes.md
    ```

4. **Test the candidate.** Merge nothing else into `develop` meanwhile, since the release ships whatever `develop` holds. A fix goes into `develop` as usual, with its changelog entry under `[X.Y.Z]` rather than `[Unreleased]`. Then tag the next candidate, `rc.N+1`.

5. **Release** once a candidate passes, from step 3 of the release procedure. In step 4, open the release pull request from the tested tag instead of the tip of `develop`, so a merge into `develop` during testing cannot reach the release.

    ```bash
    git push upstream 'vX.Y.Z-rc.N^{commit}:refs/heads/chore/merge-develop-into-main'
    ```

## Hotfix procedure

A hotfix patches a released version without shipping the rest of `develop`.

1. **Fix on a hotfix branch.** Branch `hotfix/<name>` from `main`, make the fix, run the pre-release checks, and add a `## [X.Y.Z] - YYYY-MM-DD` section to `CHANGELOG.md` for the new patch version, holding only the fix.

2. **Release the hotfix.** Open a pull request into `main` and merge it with a merge commit. Then tag and publish it as in steps 5 and 6 of the release procedure.

3. **Merge `main` back into `develop`** through a pull request from a branch such as `chore/merge-main-into-develop`. Skipping this makes the next release likely to conflict. If `CHANGELOG.md` conflicts, keep both sides, with the hotfix section below `[Unreleased]`.
