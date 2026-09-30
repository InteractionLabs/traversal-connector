# dependency-policy

This repository vendors the shared policy action because a public repository
cannot call actions or reusable workflows from the private infrastructure
repository. `SOURCE` records the exact infrastructure commit, and the vendor
test locks the copied policy files to that revision.

Only the exact dependency-policy caller and action may follow `main`; every
other GitHub Action must use a full commit SHA. The vendor test keeps the public
copy byte-for-byte aligned with its declared infrastructure source.

This action blocks any new third-party dependency published less than seven days
ago. [`dependency-policy.yml`](../../workflows/dependency-policy.yml) calls
[`reusable-dependency-policy.yml`](../../workflows/reusable-dependency-policy.yml),
which runs it.

## Evidence cache

To avoid asking a registry the same question on every run, the action caches the
publication timestamp of each coordinate it has checked, keyed on
`(ecosystem, name, version)`.

### Entries never expire

A cached entry stores `published_at` and `eligible_at` (`published_at` + cooldown)
and has no TTL. Every run still compares `eligible_at` against the current time, so a
release that is blocked today becomes eligible once its cooldown passes, with no new
registry lookup.

That is only sound when a registry guarantees that a coordinate's publication time
can never move later. The cooldown exists to catch a freshly published (possibly
hijacked) artifact. If the registry lets new bytes appear under an old coordinate,
a forever cache would keep reporting the old, eligible timestamp for them.

### Which ecosystems are cached

| Ecosystem | Cached | Why |
| --- | :---: | --- |
| npm | yes | A `name@version` can never be republished, even after unpublish, so `time[version]` is fixed. |
| Go | yes | The timestamp is the module index's first-observed time, which never changes; the checksum database pins version contents. |
| GitHub commit | yes | The key is a full commit SHA, which is content-addressed. |
| crates.io | yes | Versions cannot be re-uploaded and yanking does not change `created_at`. Edge case: crates.io allows deleting a whole crate in narrow circumstances; if the name were later re-registered and the same version published, the cached time would be stale. Accepted as low risk. |
| Maven Central | yes | Releases are immutable. No discoverer currently emits Maven coordinates. |
| PyPI (`uv.lock`) | yes, keyed on file hashes | See [PyPI](#pypi) below. |
| PyPI (`requirements.txt`, `pyproject.toml`) | **no** | These pin a version but no file hashes, so any file under that version could be installed. |
| GitHub release | **no** | A release can be deleted and recreated on the same tag with new assets, which gives it a new `published_at`. A cached timestamp would let a swapped asset through. |

The set lives in `CACHEABLE_ECOSYSTEMS` in
[`policy.py`](policy.py). Only add an ecosystem to it
when its registry guarantees that a coordinate's publication time cannot move later.

### PyPI

A PyPI version isn't immutable: filenames can't be reused, but new files (for
example a new platform wheel) can be added to an existing version at any time. The
policy takes the newest upload across a version's files, so a late upload has to
push eligibility back. A cache keyed on `(name, version)` alone would hide it.

`uv.lock` records the sha256 of every file it may install, and uv refuses any file
whose hash isn't locked. So for `uv.lock` dependencies:

- The locked hashes are part of the coordinate. A lock refresh that adds a file under
  an existing version shows up as a new dependency and is checked again.
- The cache key includes the sorted hashes, so a different file set never reuses an
  entry.
- On a lookup, every locked hash must appear in PyPI's file list for that version, or
  the dependency is `unknown`. The cached timestamp is therefore at least as late as
  every locked file's upload.

A file uploaded after the entry was cached can't be installed without changing the
lock, which changes the key. So the entry never needs to expire.

### Possible follow-up

GitHub releases could be cached the same way if the key included the release ID and
the asset ID or digest.

### Invalidating the cache

To drop every cached entry, bump `CACHE_SCHEMA` in `policy.py` and the
`dependency-policy-evidence-vN-` key in
[`reusable-dependency-policy.yml`](../../workflows/reusable-dependency-policy.yml). Changing
the cooldown also invalidates the cache, because the file records `cooldown_seconds`.
