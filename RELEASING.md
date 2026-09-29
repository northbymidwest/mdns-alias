# Releasing

`.github/workflows/release.yml`, dispatched by hand. The workflow does the
publishing; what is left to a person is the part that needs judgement.

## By hand, first

1. Bump `version` in `Cargo.toml`, and run `cargo check` so `Cargo.lock`
   follows.
2. Cut the `CHANGELOG.md` section: retitle `## Unreleased` to `## <version> -
   <publish date>`. The workflow uses that section verbatim as the release
   notes; it refuses to run if the section is missing or empty, and also if
   anything is still left under `Unreleased`. Do not leave an empty
   `Unreleased` behind: the next change adds it back.
3. Commit, push, and **wait for CI to finish**. The workflow checks that CI is
   green on the exact commit; dispatching before it completes is refused.

## Then

Actions -> release -> Run workflow. Give the version without a leading `v`
(`0.1.0`) and untick `dry_run`. Its first job, `preflight`, has no write
scope and needs no approval: it runs every check below and writes a summary
on the run page saying what approving will do. The images then build on an
amd64 and an arm64 runner and are pushed by digest, untagged. Read the
summary, then approve `publish` when it pauses: it is the only job behind the
`release` environment's reviewer, and the one that makes anything visible. It
tags `ghcr.io/northbymidwest/mdns-alias:<version>` over both digests, moves
`latest` to it, attests its provenance and SBOM, and creates the `v<version>`
tag and GitHub release.

`dry_run` is on by default. The asymmetry is deliberate: forgetting to untick
it costs a re-run, forgetting to tick it publishes. A dry run builds both
images and pushes nothing.

Two tags per release: the exact version, which never moves once pushed, and
`latest`, which moves to every release, including a re-release of an older
line. There is no `0.1` or `0`. Pin the version or the digest for anything
deployed; `latest` is for trying it out.

## What it refuses to publish

- a version that does not match `Cargo.toml`
- a version whose git tag or image tag already exists
- a commit whose CI is not green
- a version with no `CHANGELOG.md` section, or one left empty
- a `CHANGELOG.md` still carrying entries under `## Unreleased`

A failed preflight leaves nothing behind. A failure after `build` leaves at
most untagged digests in the registry, which nothing references.

## The first release

GitHub creates the package on the first push. If it comes up private, make it
public once under the package's settings; later releases keep that.

## One-time setup

The `release` environment, the tag ruleset and the deploy key that lets the
workflow push a protected `v*` tag are provisioned by
`scripts/setup-release-tagging.sh` in northbymidwest/gh-actions.
