# 카드 3 실행 절차

- 작성일: 2026-09-10
- 상태: 실제 데이터 서버와 실행 환경이 준비되면 순서대로 수행합니다.

## 실행 전 조건

1. Inria 수정 OpTC 서버가 범위 요청에 HTTP 206을 반환해야 합니다.
2. PIDSMaker가 고정된 commit `ae1e9fd42604c769c01b2eaed6fb7f65e27f3cac`으로 준비되어야 합니다.
3. PostgreSQL과 CUDA를 사용할 수 있는 실행 환경이 필요합니다.
4. [고정 입력](../config/study_inputs.json), [실험 설계](EXPERIMENT_DESIGN.md), [탐지기 선택](DETECTOR_SELECTION.md)을 변경하지 않은 상태여야 합니다.

실행 호스트에서는 먼저 다음 명령으로 PostgreSQL·Docker·NVIDIA 도구, 메모리와 디스크 상태를 기록합니다. 기존 결과를 덮어쓰지 않도록 매번 새 파일명을 사용합니다.

```powershell
python scripts/check_experiment_environment.py --output environment-check.json
```

## 1. 선택 로그 확보

정상 학습·검증용으로 2019-09-19~22의 SysClient0201, SysClient0501, SysClient0051을 확보합니다. 공격 평가용으로는 `study_inputs.json`의 세 `primary_cases`를 사용합니다.

각 날짜·호스트 조합에서 먼저 TAR 헤더를 색인화합니다. 이 명령은 30개 헤더 단위로 중단되며, 다시 실행하면 기록한 위치부터 이어갑니다.

```powershell
python scripts/index_inria_tar.py --date 2019-09-19 --host 201
python scripts/fetch_inria_members.py --date 2019-09-19 --host 201
```

나머지 날짜와 호스트에도 같은 순서로 적용합니다. 다운로드 도구는 HTTP 범위, TAR 멤버 크기, gzip CRC, 모든 JSONL 행, SHA-256과 이벤트 수를 확인하고 `data/inria_selected/<date>/manifest.jsonl`에 기록합니다. 실패한 부분 파일은 성공 파일로 취급하지 않습니다.

## 2. 입력과 정답 검증

1. 각 선택 로그의 manifest에서 `gzip_and_jsonl_valid=true`와 이벤트 수를 확인합니다.
2. 세 공격 사례의 라벨 SHA-256이 `study_inputs.json`과 같은지 확인합니다.
3. 실제 이벤트의 timestamp, 이벤트 ID, 원본 파일·행 번호로 정렬 규칙을 확정하고 입력 SHA-256과 이벤트 수를 기록합니다.
4. 유실 입력을 만들기 전에 완전한 수정 입력으로만 정답을 고정합니다. 유실 뒤 라벨을 다시 생성하지 않습니다.

## 3. 유실 변형 생성

각 고정된 평가 입력에 대해 아래 순서로 수행합니다. `SOURCE_SHA256`에는 해당 입력 파일의 SHA-256, `EVENT_COUNT`에는 검증한 JSONL 이벤트 수를 넣습니다.

```powershell
python scripts/loss_masks.py --events EVENT_COUNT --rate 0.10 --seed 0 --pattern random --source-sha256 SOURCE_SHA256 --output masks/random-10-seed-0.json
python scripts/apply_loss_mask.py --input INPUT.json.gz --mask masks/random-10-seed-0.json --output variants/random-10-seed-0.json.gz --manifest variants/random-10-seed-0.manifest.json
```

무작위·연속 유실 각각에 대해 시드 0~29와 1%, 5%, 10%, 20%를 적용합니다. 출력 manifest의 입력·마스크·출력 SHA-256, 삭제 수, 전후 이벤트 수를 보존합니다. 마스크와 적용 도구는 공격 라벨을 읽지 않습니다.

## 4. 무유실 기준 실행과 중단 조건

PIDSMaker KAIROS는 2019-09-19~21 정상 자료로 학습하고, 2019-09-22 정상 자료의 최대 손실로 임계값을 한 번 정합니다. 세 공격 사례는 동일 체크포인트·임계값·초기 추론 상태에서 실행합니다.

무유실 기준에서 각 사례의 고정 수정 라벨 노드 중 하나 이상이 임계값을 엄격히 초과해야 합니다. 하나라도 충족하지 못하면 유실 비교를 시작하지 않고, 해당 탐지기가 이 가설을 검증하지 못했다는 결과로 기록합니다.

## 5. 결과 보관과 재확인

각 실행에 입력·코드·가중치 해시, 날짜·호스트·구간, 시드, 유실률, 삭제 수, 탐지 결과, 시작·종료 시각, 오류를 남깁니다. 실패한 실행도 삭제하지 않습니다.

코드와 문서의 짧은 확인은 다음 명령으로 수행합니다.

```powershell
python -W error::ResourceWarning -m unittest discover -s tests -v
python scripts/loss_masks.py --help
python scripts/apply_loss_mask.py --help
```

첫 명령은 유실 마스크·마스크 적용·고정 입력 검증을 실행합니다. 나머지 두 명령은 실행 인자를 확인합니다. 실제 로그가 확보된 뒤에는 선택 로그 manifest와 변형 manifest의 SHA-256·이벤트 수를 함께 대조합니다.
