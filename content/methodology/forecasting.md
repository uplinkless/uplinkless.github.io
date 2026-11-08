---
title: "전망 작성과 채점"
description: "전망을 쓰고 맞았는지 판정하는 방법. How forecasts are written and scored."
weight: 5
hidemeta: true
---
## 쓰는 법

- 입력: 후보 그룹의 공개된 목표와 과거 행태, 최근 정치·지정학 사건(뉴스, 정부 권고). 출처 링크와 날짜를 반드시 단다.
- 시나리오는 2~3개다. 시나리오마다 내용, 조건, 지켜볼 징후, 기한, 확률(%와 표준 표현), 대응 권고(탐지 룰, 방어 조치)를 적는다.
- 기한이 지난 뒤 맞았는지 가릴 수 있는 전망만 쓴다.

## 기록부

전망은 `data/forecasts.yaml`에 등록한다. 날짜는 따옴표로 감싼 문자열로 쓴다.

    items:
      - id: "F-2026-001"
        created: "2026-11-15"
        deadline: "2027-02-15"
        statement: "..."
        probability: 30
        post: "/analyses/2026/2026-11-15-slug/"
        status: "open"
        resolution: ""

`status`는 `open`, `resolved_true`, `resolved_false` 중 하나다. 판정할 때 `resolution`에 근거와 출처를 적는다.

## 채점

판정된 전망마다 (확률 − 결과)²를 구해 평균한다. 결과는 맞으면 1, 틀리면 0이다. 0에 가까울수록 정확하고, 모든 전망을 50%로 냈다면 0.25다. [Forecasts](/forecasts/) 페이지가 이 점수를 계산해 보여 준다.
