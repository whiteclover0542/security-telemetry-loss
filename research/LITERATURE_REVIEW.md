# 선행 연구 검토 — 보안 이벤트 유실과 공격 탐지

- 작성일: 2026-09-10
- 관심 분야: 정보보안 / 침입 탐지·디지털 포렌식·운영체제 관측
- 연구 주제: 보안 이벤트 유실의 시간적 구조가 공격 탐지와 원인 추적에 미치는 영향

## 검토 질문

1. 운영체제 감사 로그와 provenance graph는 공격 탐지·원인 추적에 어떻게 사용되는가?
2. 감사 이벤트가 누락될 수 있는 원인과 누락의 알려진 영향은 무엇인가?
3. 기존 로그 축약 연구는 보안 분석에 필요한 정보를 어떻게 보존하는가?
4. 기존 provenance 기반 침입 탐지 연구는 입력 이벤트 유실의 시간적 구조를 평가했는가?
5. OpTC로 공격 단위 유실 실험을 재현할 수 있는가?

## 이미 알려진 사실

Provenance 기반 침입 탐지는 운영체제 사건을 객체와 행위자의 관계로 연결해 시스템 실행 이력과 장거리 의존관계를 분석한다. 이 구조는 개별 로그 행보다 공격의 인과관계와 실행 경로를 표현하기 쉽지만, 그 설명력은 수집된 사건에 의존한다 [1].

감사 로그 수집원은 항상 완전하지 않다. Linux Audit은 버퍼가 가득 차거나 저장 정책이 오래된 레코드를 지우거나 새 레코드를 무시하도록 설정되면 레코드를 잃을 수 있다. 파일 디스크립터와 대상 파일을 연결하는 레코드가 빠지면 이후 읽기·쓰기 활동도 해당 파일로 추적되지 않을 수 있다 [2]. 따라서 단일 누락이 한 간선의 부재로 끝나지 않고 뒤따르는 인과관계의 불완전성으로 이어질 수 있다.

작은 정적 실험에서는 누락된 시스템 호출을 provenance graph의 차이로 식별할 수 있었다. Chan 외는 약 20개 시스템 호출로 만든 기준 기록에서 1~3개 호출을 제거해 ProvMark의 무결성 검사를 시연했다 [2]. 후속 연구는 비결정적 실행에서 시스템 호출 하나가 빠지면 손상된 실행이 다른 정상 실행 경로와 같아 보여 거짓 음성이 생길 수 있고, 목표 실행 경로를 찾지 못할 수 있다고 설명한다 [3]. 이 결과는 누락된 사건의 의미와 실행상의 위치가 중요할 가능성을 보여주지만, 실제 공격 데이터에서 연속 유실과 분산 유실의 탐지 성능을 비교한 결과는 아니다.

로그 양을 줄이는 연구는 사건을 임의로 버리는 것과 분석 의미를 보존하는 축약을 구분한다. KCAL은 중복 사건을 억제하면서 생성된 인과 graph에 필요한 정보가 남는지를 수동 비교해 손실 없는 축약이라고 평가했다 [4]. ELISE는 어떤 사건이 중복인지는 분석 방법에 따라 달라지며, 한 분석에서 중복인 사건도 빈도 기반 이상 탐지에는 필요할 수 있다고 지적한다. 여러 보안 분석을 일반적으로 지원하려면 손실 없는 압축이 필요하다는 것이 ELISE의 설계 근거다 [5]. 이 연구들은 정보 보존을 목표로 한 축약이며, 수집 장애로 발생하는 비의도적 유실과 같지 않다.

KAIROS는 시스템 감사 사건의 시간적 변화를 학습해 사건별 이상 점수를 계산하고 공격 흔적을 재구성한다 [6]. Bilot 외는 KAIROS를 포함한 여덟 provenance 기반 침입 탐지 시스템을 공통 파이프라인에서 비교하면서, 공격 단위 성능을 기존 노드 단위 지표만으로 설명하기 어렵고 테스트 결과를 본 임계값 조정이 데이터 누출을 일으킨다고 지적했다. 이들은 공격 탐지율과 노드 정밀도의 관계를 나타내는 ADP 지표와 공개 프레임워크 PIDSMaker를 제시했다 [7]. 따라서 이번 실험은 공격 사례 단위 결과를 기록하고 탐지기·임계값을 유실 결과 확인 전에 고정해야 한다.

OpTC 공개 자료는 Windows 10 엔드포인트의 eCAR 사건, 정상 구간, 공격 평가 구간과 레드팀 정답 문서를 포함한다. 제공자는 `short` 구간에 결측 데이터가 있다고 명시하며, 중복 프로세스 객체, 일부 모듈 적재 해시 누락, 파일 경로 표현 차이도 별도 정오표에 기록했다 [8]. 그러므로 이번 연구가 인위적으로 추가한 유실량을 원본 데이터의 절대적인 전체 유실량으로 해석할 수 없다. `short` 구간은 주 비교의 무유실 기준에서 제외하고, `evaluation` 구간도 “완전한 현실”이 아니라 추가 유실 전 기준 자료로 표현해야 한다.

## 이번 연구가 새로 검증할 주장

최종 가설은 다음과 같다.

> OpTC의 공격별 평가 구간을 고정된 탐지기로 재생할 때, 추가 유실률과 제거 이벤트 수가 같다면 시간적으로 연속된 유실은 균등 무작위 유실보다 탐지 결과의 시드 간 변동을 크게 만든다.

기존 연구로부터 가져오는 전제는 감사 사건의 누락이 provenance 완전성과 탐지·경로 식별을 훼손할 수 있다는 점이다 [1]–[3]. 특히 [3]은 시스템 호출 하나가 빠지면 손상된 실행이 정상 실행 경로와 같아 보여 거짓 음성이 생길 수 있다고 보고한다. 이는 유실의 총량보다 **어느 사건이 사라졌는지**가 결과를 가른다는 뜻이므로, 평균 차이보다 결과의 변동을 다루는 이번 가설과 직접 연결된다.

이번 연구가 직접 검증할 부분은 총 추가 유실률과 제거 개수가 같을 때 유실의 시간적 집중만으로 탐지 결과의 예측 가능성이 달라지는지다. 확인한 문헌은 개별 호출 제거, 의미 보존형 로그 축약, 완전한 입력을 전제로 한 탐지 성능을 다루었지만 이 비교 결과를 제공하지 않는다 [2]–[7]. 이는 현재 검토 범위에서 확인되지 않았다는 뜻이며, 해당 주장의 절대적인 최초성을 뜻하지 않는다.

가설은 다음 결과로 기각하거나 판단을 유보할 수 있다.

- 연속 유실의 시드 간 표준편차가 균등 무작위 유실보다 크지 않으면 방향 가설을 지지하지 않는다.
- 세 사례에서 변동 차이의 부호가 일치하지 않으면 일반화하지 않고 사례별로만 보고한다.
- 함께 등록한 평균 비교에서 연속 유실의 탐지율 감소가 더 크지 않아도 그 자체를 결과로 보고한다. 측정한 삭제 구간 길이를 고려하면 평균 차이는 작거나 반대 방향일 수 있다고 결과 확인 전에 예상한다.

## 연구 설계에 반영할 제약

- 탐지기, 전처리, 임계값, 공격 평가 구간과 통계 절차는 유실 조건의 결과를 보기 전에 고정한다 [7].
- 1차 결과는 공격 사례 탐지율과 무유실 기준 대비 감소량으로 기록한다. 노드 단위 정밀도와 정상 구간 오탐도 함께 보고한다 [7].
- 연속 유실과 균등 무작위 유실은 공격별 평가 구간에서 정확히 같은 수의 사건을 제거한다.
- 원본 OpTC의 알려진 결측·스키마 문제와 인위적으로 추가한 유실을 분리해 기록한다 [8].
- 유실 없는 기준에서 탐지되지 않은 공격은 1차 “유실로 인한 감소” 계산의 분모에서 제외하되 전체 라벨 공격 결과에는 남긴다.
- 동일한 공격 로그에 여러 유실 시드를 적용한 결과를 서로 독립적인 공격 표본으로 해석하지 않는다.

## 확인 과정에서 제외한 항목

| 항목 | 제외 이유 |
| --- | --- |
| COMIDDS의 OpTC 소개 페이지 | 데이터 발견과 교차 확인에는 유용하지만 제3자 요약이다. 데이터 구조와 알려진 문제의 근거는 제공자 문서 [8]을 우선한다. |
| FiveDirections/OpTC-data 저장소의 사용자 라벨링 이슈 및 개인 저장소 | 작성자가 정확하지 않을 수 있다고 명시한 비공식 라벨이다. 생성 절차와 공식 정답의 일치가 검증되지 않아 공격 정답으로 쓰지 않는다. |
| *DeepTaskAPT: Insider APT Detection Using Task-tree Based Deep Learning* | OpTC 기반 탐지 연구지만 현재 확인한 초록은 이벤트 유실 구조나 수집 완전성을 평가하지 않는다. 가설의 핵심 논거에서 제외하고 탐지기 후보 조사 때만 다시 검토한다. |
| 2026년 Preprints.org의 불완전 정보 침입 탐지 설문 | 동료 심사를 확인할 수 없는 사전 공개 설문이며, 본 연구 주제와 매우 가깝지만 1차 연구의 실험 근거를 대신할 수 없다. 참고문헌에서 제외한다. |
| 연구 블로그·상업 사이트·검색 결과 요약 | 출처 발견에만 사용했다. 서지와 주장을 출판기관 원문에서 확인할 수 없는 자료는 논거와 참고문헌에 넣지 않는다. |

## 출처 확인 방법

검색 결과는 후보 발견에만 사용했다. 각 채택 문헌은 출판기관의 논문 페이지와 공개 PDF에서 제목, 저자, 발표 연도, 발표처를 대조했다. 가설에 연결한 문장은 초록, 방법, 평가 또는 한계 절에서 직접 확인했다. 데이터의 구성과 알려진 오류는 데이터 제공자의 README, 형식 문서와 정오표를 확인했다. 마지막 확인일은 2026-09-10이다.

카드 3에서는 다음을 추가로 확인해야 한다.

1. OpTC 원자료 또는 PIDSMaker 전처리 자료에 실제로 접근할 수 있는지
2. 레드팀 정답을 사건·호스트·시간 구간에 재현 가능하게 대응시킬 수 있는지
3. 선택한 탐지기의 무유실 기준 결과와 고정 가중치가 재현되는지
4. 입력 사건을 graph 생성 전 단계에서 제거하고 동일한 파이프라인으로 다시 처리할 수 있는지

## 참고문헌

[1] X. Han, T. Pasquier, and M. Seltzer, “Provenance-based Intrusion Detection: Opportunities and Challenges,” in *10th USENIX Workshop on the Theory and Practice of Provenance (TaPP 2018)*, 2018. https://www.usenix.org/conference/tapp2018/presentation/han

[2] S. C. Chan, A. Gehani, H. Irshad, and J. Cheney, “Integrity Checking and Abnormality Detection of Provenance Records,” in *12th USENIX Workshop on the Theory and Practice of Provenance (TaPP 2020)*, 2020. https://www.usenix.org/conference/tapp2020/presentation/chan

[3] S. C. Chan, J. Cheney, and P. Bhatotia, “Provenance Expressiveness Benchmarking on Non-deterministic Executions,” in *13th USENIX Workshop on the Theory and Practice of Provenance (TaPP 2021)*, 2021. https://www.usenix.org/sites/default/files/tapp2021_chan.pdf

[4] S. Ma et al., “Kernel-Supported Cost-Effective Audit Logging for Causality Tracking,” in *2018 USENIX Annual Technical Conference (USENIX ATC 2018)*, 2018. https://www.usenix.org/conference/atc18/presentation/ma-shiqing

[5] H. Ding, S. Yan, J. Zhai, and S. Ma, “ELISE: A Storage Efficient Logging System Powered by Redundancy Reduction and Representation Learning,” in *30th USENIX Security Symposium (USENIX Security 2021)*, 2021. https://www.usenix.org/conference/usenixsecurity21/presentation/ding

[6] Z. Cheng et al., “KAIROS: Practical Intrusion Detection and Investigation Using Whole-system Provenance,” in *2024 IEEE Symposium on Security and Privacy*, 2024. https://doi.org/10.48550/arXiv.2308.05034

[7] T. Bilot et al., “Sometimes Simpler Is Better: A Comprehensive Analysis of State-of-the-Art Provenance-Based Intrusion Detection Systems,” in *34th USENIX Security Symposium (USENIX Security 2025)*, 2025. https://www.usenix.org/conference/usenixsecurity25/presentation/bilot

[8] Five Directions, “Operationally Transparent Cyber (OpTC) Data Release,” dataset documentation and errata, data collected 2019. https://github.com/FiveDirections/OpTC-data
