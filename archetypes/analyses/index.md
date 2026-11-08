---
title: "{{ .File.ContentBaseName }}"
date: {{ .Date }}
draft: true
families: []
attack: []
tools: []
groups: []
attribution: []
#  - group: "Group name"
#    score: 0            # percent, from evidence/attribution.csv
#    band: "낮음"         # ICD 203 band, see /methodology/attribution-scoring/
#    robustness: "보통"   # 견고 / 보통 / 취약
#    calibrated: false    # if false, write 미교정 next to the score in the body
forecasts: []
shared_with: []
#  - agency: "KISA"
#    date: 2026-11-20
tags: []
samples: []
#  - sha256: ""
#    source: ""
#    filetype: ""
environment: "Windows 11 x64 VM, network-isolated (no uplink), reverted to a clean snapshot before each run"
ai_usage: ""
---

TL;DR. English summary in two or three sentences: what the sample is, what it does, and the strongest assessed link.

<!--more-->

## 1. English Summary

- **Key findings:**
- **Assessed links:** group, %, band, robustness (mark uncalibrated scores)
- **Detection:** file / endpoint / network coverage

## 2. 개요

## 3. 트리아지

## 4. 정적 분석

## 5. 언패킹·복호화

## 6. 동적 분석

## 7. 설정 추출

## 8. 탐지

| 층 | 형식 | 룰 파일 | 검증 결과 |
|---|---|---|---|
| 파일 | YARA | | |
| 엔드포인트(EDR) | Sigma | | |
| 네트워크(NDR) | Suricata, Zeek | | |

## 9. IoC·ATT&CK

## 10. 공격 그룹 유사도

| 그룹 | % | 표현 | 견고성 | 교정 |
|---|---|---|---|---|

근거 표는 `evidence/attribution.csv`에 있다.

## 11. 적대적 검증

| 시도 | 결과 |
|---|---|
| 기저율 점검 | |
| 근거 제거 민감도 | |
| 위장 징후 | |
| 경쟁 가설 | |
| AI 비평 | |

## 12. 맥락과 전망

## 13. 기관 공유

## 14. 한계와 남은 질문

## 15. 작업 구분과 AI 사용 내역

| 단계 | 자동(도구) | AI | 직접 | 근거 |
|---|---|---|---|---|
