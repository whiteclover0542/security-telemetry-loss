# 재현 방법

논문 「CVSS 점수는 악용 확인 시점을 예고하는가 — CISA KEV 카탈로그 815건에 대한 사전등록 재분석」의
모든 수치·표·그래프를 다시 만드는 절차다.

## 1. 필요한 것

- **Python 3.8 이상.** 그 외에 설치할 것이 없다.
- 외부 패키지(numpy, pandas, scipy, matplotlib)를 **쓰지 않는다.** 통계 함수와 그래프를 표준 라이브러리로 직접 구현했다.
- 네트워크는 **필요 없다.** 원자료가 패키지에 들어 있다.

확인:

```
python --version
```

## 2. 폴더 구성

```
thesis/
├── paper/
│   ├── paper.md                     완성 논문
│   └── figures/
│       ├── fig1_scatter.svg         그림 1 (분석 결과로 생성됨)
│       └── fig2_severity.svg        그림 2 (분석 결과로 생성됨)
├── data/
│   ├── raw/                         원자료 — 절대 수정하지 않는다
│   │   ├── kev_2026-09-08.json      CISA KEV 카탈로그 스냅샷 (1,695건)
│   │   └── nvd_kev_2026-09-08.json  NVD CVE API 2.0 hasKev 응답 (1,695건)
│   └── processed/                   생성물
│       ├── kev_delay.csv            분석용 데이터 (1,695행)
│       ├── build_report.json        결합 과정 기록 (결측·불일치 목록)
│       ├── results.json             모든 분석 수치
│       └── results.md               논문에 실린 표
├── scripts/
│   ├── fetch_data.py                원자료 내려받기 (네트워크 필요, 선택)
│   ├── build_dataset.py             원자료 결합·정제
│   ├── stats.py                     통계 함수 구현
│   ├── test_stats.py                통계 구현 검증
│   └── analyze.py                   분석·표·그래프 생성
├── ASSIGNMENT.md                    과제 요구사항
├── PROGRESS.md                      작업 과정 기록 (판단 근거와 설계 변경 이력)
└── REPRODUCE.md                     이 문서
```

## 3. 실행 (3단계, 1분 이내)

프로젝트 루트에서 순서대로 실행한다.

### 3.1 통계 구현이 맞는지 먼저 검증한다

```
python scripts/test_stats.py
```

기대 출력의 마지막 줄: `모든 검증 통과`

손으로 계산할 수 있는 값(예: Kruskal-Wallis H = 27/7, Spearman ρ = 4/√20)과
공표된 임계값(카이제곱 3.8414588 → p = 0.05 등) 22개를 대조한다.
여기서 실패하면 뒤 단계의 수치를 믿을 수 없다.

### 3.2 원자료를 결합한다

```
python scripts/build_dataset.py
```

기대 출력:

```
스냅샷            : 2026-09-08 (catalogVersion 2026.09.04)
KEV 원자료        : 1695 건
NVD 원자료        : 1695 건 (totalResults=1695)
결합 성공         : 1695 건
  KEV에만 있음    : 0
  NVD에만 있음    : 0
CVSS v3.1 결측    : 4 건 ['CVE-2018-14634', 'CVE-2025-61932', 'CVE-2025-6218', 'CVE-2026-0770']
2차 출처 점수 사용: 342 건
창설일 이전 공개  : 877 건 (주 분석 제외)
주 분석 표본 n    : 815 건
지연 음수         : 63 건 [...]
```

`data/processed/kev_delay.csv`(1,695행)와 `build_report.json`이 만들어진다.

### 3.3 분석한다

```
python scripts/analyze.py
```

`data/processed/results.json`, `results.md`, `paper/figures/fig1_scatter.svg`,
`fig2_severity.svg`가 만들어지고 논문의 표가 화면에 출력된다.

## 4. 결과가 맞는지 확인하는 법

논문의 핵심 수치와 대조한다. 아래 값이 그대로 나와야 한다.

| 확인할 것 | 값 | 어디서 보나 |
| --- | --- | --- |
| 주 분석 표본 | 815 | `results.json > counts.primary_sample` |
| **Spearman ρ (주 분석)** | **+0.0526** | `results.json > correlation.primary.rho` |
| p 값 | 0.1333 | `results.json > correlation.primary.p` |
| 95% 신뢰구간 | [−0.017, +0.122] | `results.json > correlation.primary.ci95` |
| 판정 | 관계 없음 | `results.json > correlation.primary.verdict` |
| Kruskal-Wallis H | 8.262 (p = 0.0409) | `results.json > kruskal_wallis` |
| 효과크기 ε² | 0.0101 | `results.json > kruskal_wallis.epsilon_squared` |
| 지연 중앙값 | 8일 | `results.json > delay_describe_primary.median` |
| 지연 음수 건수 | 63건 (7.7%) | `results.json > negative_delay` |

부트스트랩 신뢰구간은 난수를 쓰지만 **seed를 20260908로 고정**했으므로 몇 번을 돌려도 같은 값이 나온다.

한 줄로 확인:

```
python -c "import json;r=json.load(open('data/processed/results.json',encoding='utf-8'));c=r['correlation']['primary'];print('n=%d rho=%+.4f p=%.4f -> %s'%(c['n'],c['rho'],c['p'],c['verdict']))"
```

기대 출력:

```
n=815 rho=+0.0526 p=0.1333 -> 가설 기각 — 관계 없음 (|rho| <= 0.1)
```

## 5. 원자료를 새로 받으려면 (선택)

```
python scripts/fetch_data.py
```

CISA KEV와 NVD에서 오늘 날짜로 새 스냅샷을 받는다. 계정이나 API 키가 필요 없다.

**주의:** KEV 카탈로그는 계속 갱신된다. 새로 받으면 건수와 분석 결과가 이 논문과 **달라진다.**
논문을 그대로 재현하려면 이 스크립트를 실행하지 말고, 패키지에 들어 있는 2026-09-08 스냅샷을 쓰면 된다.
`build_dataset.py`는 `data/raw/`에서 파일명 날짜가 가장 최근인 스냅샷을 자동으로 고른다.

네트워크를 쓰지 않고 스냅샷만 검사하려면:

```
python scripts/fetch_data.py --check --date 2026-09-08
```

## 6. 데이터 출처

| 데이터 | 제공 기관 | URL | 받은 날짜 |
| --- | --- | --- | --- |
| Known Exploited Vulnerabilities Catalog | CISA | https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json | 2026-09-08 |
| NVD CVE API 2.0 (`hasKev` 필터) | NIST NVD | https://services.nvd.nist.gov/rest/json/cves/2.0?hasKev&resultsPerPage=2000 | 2026-09-08 |

둘 다 공개 데이터이며 로그인·API 키 없이 받을 수 있다.

## 7. 그래프를 보려면

`paper/figures/*.svg`는 웹 브라우저에서 바로 열린다. 별도 도구가 필요 없다.

## 8. 분석을 바꿔 보려면

- **표본 기준일 변경**: `scripts/build_dataset.py`의 `KEV_LAUNCH` 상수.
- **부트스트랩 반복 수·seed**: `scripts/analyze.py`의 `BOOTSTRAP_REPS`, `SEED`.
- **판정 기준**: `scripts/analyze.py`의 `verdict()` 함수. 논문의 기준은 데이터를 보기 전에 확정한 것이므로,
  바꿔서 얻은 결과는 사전등록 분석이 아니라는 점을 밝혀야 한다.
