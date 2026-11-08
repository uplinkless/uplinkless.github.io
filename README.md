# uplinkless.github.io

Malware analysis, detection rules, evidence-based attribution and forecasts. Published at https://uplinkless.github.io/.

신규 악성코드 분석, 탐지 룰, 근거 기반 공격 그룹 유사도 평가와 전망 기록.

## Layout

- `content/analyses/YYYY/YYYY-MM-DD-slug/`: one folder per analysis with `index.md`, `iocs.csv`, `rules/`, `tools/`, `evidence/attribution.csv`, `images/`
- `content/techniques/YYYY/YYYY-MM-DD-slug/`: technique reproductions with my own benign programs (`src/`)
- `content/methodology/`: how posts are analyzed, judged and published
- `data/forecasts.yaml`: forecast registry shown at `/forecasts/`
- `scripts/prepublish_check.py`: pre-publish safety check; `scripts/test_*.py`: tests

## New post

```
hugo new content --kind analyses analyses/2026/2026-11-15-slug
hugo new content --kind techniques techniques/2026/2026-11-15-slug
```

## Checks

```
py -3 scripts/test_prepublish_check.py
py -3 scripts/test_site_build.py
py -3 scripts/prepublish_check.py --all
```

The pre-commit hook (`git config core.hooksPath .githooks`) runs the check on staged files with a private deny-list kept outside this repository.

## No samples

This repository never contains malware samples or other executables. Posts list hashes and public source links only.

## License

Code, detection rules and scripts: MIT (`LICENSE`). Text and images under `content/`: CC BY 4.0 (`LICENSE-CONTENT.md`).
