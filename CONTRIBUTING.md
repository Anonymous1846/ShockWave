# Contributing to ShockWave

ShockWave is open source under the **Apache License 2.0**. You may use, modify,
and redistribute it freely, provided you keep the copyright/`NOTICE` attribution
and mark any files you changed (Apache-2.0 §4).

## Ownership

Sharath Sunil is the creator, copyright owner, and sole maintainer of the
canonical repository. Contributions are welcome via pull request and, once
merged, are credited in [`AUTHORS`](AUTHORS).

## How changes reach the project

All changes to the canonical repo go through a **pull request**. The owner is a
required reviewer (see [`.github/CODEOWNERS`](.github/CODEOWNERS)), so nothing
merges without the owner's approval — this is how the maintainer stays informed
of every change.

> Note: Apache-2.0 lets anyone fork and modify ShockWave on their own. That is
> how open source works — no license can force a third party to notify you of a
> private fork. The review gate above governs the **canonical** repository only.

## Developer Certificate of Origin (DCO)

By contributing you certify the [DCO](https://developercertificate.org/): that
you wrote the change or have the right to submit it under Apache-2.0. Certify by
signing off every commit:

```bash
git commit -s -m "your message"
```

This appends a line to the commit message:

```
Signed-off-by: Your Name <your@email>
```

PRs whose commits are not signed off will be asked to amend with `-s`.

## Submitting a change

1. Fork and branch from `master`.
2. Make the change; add/adjust a test under `tests/unit/` where it applies.
3. Run the suite: `python -m pytest tests/unit/ -q`.
4. Sign off your commits (`-s`) and open a PR describing what and why.
5. Add yourself to `AUTHORS` in the same PR.

Thanks for contributing.
