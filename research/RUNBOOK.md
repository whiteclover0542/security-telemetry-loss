# 카드 3 실행 절차

- 작성일: 2026-09-10
- 상태: 실제 데이터 서버와 실행 환경이 준비되면 순서대로 수행합니다.

## 실행 전 조건

1. Inria 수정 OpTC 서버가 범위 요청에 HTTP 206을 반환해야 합니다. 서버는 간헐적으로만 응답하므로 작은 범위 요청으로 먼저 확인합니다.
2. PIDSMaker가 고정된 commit `ae1e9fd42604c769c01b2eaed6fb7f65e27f3cac`으로 준비되어야 합니다. **Windows에서는 `core.autocrlf`를 끄고 체크아웃해야 합니다.** 켜져 있으면 셸 스크립트 22개가 CRLF로 바뀌어 리눅스 컨테이너에서 실행되지 않고, `entrypoint.sh`가 깨져 이미지가 기동하지 않습니다.

```powershell
git clone https://github.com/ubc-provenance/PIDSMaker.git external/PIDSMaker
git -C external/PIDSMaker checkout ae1e9fd42604c769c01b2eaed6fb7f65e27f3cac
git -C external/PIDSMaker config core.autocrlf false
git -C external/PIDSMaker rm --cached -r . -q
git -C external/PIDSMaker reset --hard
file external/PIDSMaker/entrypoint.sh
```

마지막 명령이 `CRLF line terminators`를 보고하면 안 됩니다.

3. Docker와 GPU 접근이 필요합니다. 아래로 확인합니다.

```powershell
docker run --rm --gpus all nvidia/cuda:11.7.1-base-ubuntu22.04 nvidia-smi --query-gpu=name,memory.total,compute_cap --format=csv
```

4. 데이터베이스 컨테이너를 올립니다. `.env.local`을 `.env`로 복사하고 `INPUT_DIR`·`ARTIFACTS_DIR`를 지정한 뒤 실행합니다. 기본 `DOCKER_PORT`는 8888이라 호스트 PostgreSQL의 5432와 충돌하지 않습니다.

```powershell
docker compose -p postgres -f compose-postgres.yml up -d
docker exec postgres psql -U postgres -tAc "SELECT datname FROM pg_database WHERE datname LIKE '%optc%'"
```

`optc_201`, `optc_501`, `optc_051`이 나와야 합니다.
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

나머지 날짜와 호스트에도 같은 순서로 적용합니다. 다운로드 도구는 HTTP 범위, TAR 멤버 크기, gzip CRC, 모든 JSONL 행, SHA-256과 이벤트 수를 확인하고 `data/inria_selected/<date>/manifest.jsonl`에 기록합니다. 실패한 부분 파일은 성공 파일로 취급하지 않으며, 실패한 시도는 같은 폴더의 `attempts.jsonl`에 남습니다.

이미 받아 둔 파일이 manifest에 없으면 다시 받지 말고 재검증으로 기록합니다. 저장된 바이트를 다시 읽어 크기·SHA-256·gzip·모든 JSON 행을 확인한 뒤 `source`를 `verified_existing_file`로 기록합니다.

```powershell
python scripts/fetch_inria_members.py --date 2019-09-20 --host 201 --verify-only
```

## 2. 입력과 정답 검증

1. 각 선택 로그의 manifest에서 `gzip_and_jsonl_valid=true`와 이벤트 수를 확인합니다.
2. 세 공격 사례의 라벨 SHA-256이 `study_inputs.json`과 같은지 확인합니다. 해시는 줄바꿈을 LF로 정규화한 바이트 기준입니다. 저장소는 LF로 보관하지만 `core.autocrlf`가 켜진 환경에서는 Git이 CRLF로 바꿔 내려받으므로, 디스크의 바이트를 그대로 해시하면 같은 커밋이 Linux에서는 통과하고 Windows에서는 실패합니다.

```powershell
git clone https://gitlab.inria.fr/fmajorcz/a_new_hope_for_darpa_optc external/corrected-optc-review
git -C external/corrected-optc-review checkout 644f41fb0a955e471f34bed016fb2bfd9c74dc04
python scripts/verify_labels.py
```

세 사례가 모두 `ok`여야 하며 종료 코드가 0입니다. 하나라도 어긋나면 라벨을 고정 입력으로 사용하지 않습니다.
3. 실제 이벤트의 timestamp, 이벤트 ID, 원본 파일·행 번호로 정렬 규칙을 확정하고 입력 SHA-256과 이벤트 수를 기록합니다.
4. 유실 입력을 만들기 전에 완전한 수정 입력으로만 정답을 고정합니다. 유실 뒤 라벨을 다시 생성하지 않습니다.

## 3. 평가 구간 위치 산출

유실은 하루 전체가 아니라 공격별 평가 구간에서만 발생시킵니다. 두 유실 방식이 같은 구간에서 같은 개수를 지워야 가설의 전제가 성립하기 때문입니다. 아래 도구가 고정 입력의 timestamp를 읽어 구간의 시작·끝 위치를 산출합니다.

시각 인자에는 UTC 오프셋을 반드시 붙입니다. OpTC timestamp는 지역 오프셋을 포함하고, PIDSMaker 설정의 시간 문자열에는 시간대 표기가 없으므로 어느 해석을 택했는지 기록에 남겨야 합니다.

```powershell
python scripts/window_positions.py --input INPUT.json.gz --start 2019-09-23T11:23:00-04:00 --end 2019-09-23T13:25:00-04:00 --output windows/scenario-1.json
```

출력의 `selection_start`, `selection_end`, `selection_event_count`를 기록합니다. 입력이 시간순으로 정렬되어 있지 않아 구간에 창 밖 이벤트가 섞이면 도구가 중단합니다. 그 경우 정렬 상태를 먼저 확인하고, 그대로 진행하기로 결정했다면 `--allow-impure-range`와 그 판단을 함께 기록합니다.

## 4. 유실 변형 생성

각 고정된 평가 입력에 대해 아래 순서로 수행합니다. `SOURCE_SHA256`에는 입력 파일의 SHA-256, `EVENT_COUNT`에는 검증한 JSONL 이벤트 수, `START`·`END`에는 3단계의 구간 위치를 넣습니다.

```powershell
python scripts/loss_masks.py --events EVENT_COUNT --rate 0.10 --seed 0 --pattern random --selection-start START --selection-end END --source-sha256 SOURCE_SHA256 --output masks/random-10-seed-0.json
python scripts/apply_loss_mask.py --input INPUT.json.gz --mask masks/random-10-seed-0.json --output variants/random-10-seed-0.json.gz --manifest variants/random-10-seed-0.manifest.json
python scripts/mask_overlap.py --input INPUT.json.gz --mask masks/random-10-seed-0.json --attack-start 2019-09-23T11:23:00-04:00 --attack-end 2019-09-23T13:25:00-04:00 --output overlaps/random-10-seed-0.json
```

무작위·연속 유실 각각에 대해 시드 0~29와 1%, 5%, 10%, 20%를 적용합니다. 출력 manifest의 입력·마스크·출력 SHA-256, 삭제 수, 전후 이벤트 수를 보존합니다. 마스크와 적용 도구는 공격 라벨을 읽지 않으며, 겹침 측정은 마스크가 만들어진 뒤에만 공격 구간을 읽습니다.

변형 파일(`variants/*.json.gz`)은 보관하지 않습니다. 해당 변형의 탐지기 실행이 끝나면 변형 파일을 삭제하고 마스크·적용 manifest·겹침 기록·실행 기록만 남깁니다. 셋을 합치면 같은 변형을 언제든 다시 만들 수 있고, 전부 보관하면 약 150GB가 필요합니다. 삭제 대상은 재생성 가능한 중간 산출물뿐이며 실행 결과는 삭제하지 않습니다.

## 5. 무유실 기준 실행과 중단 조건

PIDSMaker KAIROS는 2019-09-19~21 정상 자료로 학습하고, 2019-09-22 정상 자료의 최대 손실로 임계값을 정합니다. 호스트별로 데이터셋과 튜닝 인자가 분리되므로 사례마다 체크포인트 1개와 임계값 1개를 얻습니다. 한 사례 안에서는 무유실 기준과 모든 유실 변형이 같은 체크포인트·임계값·초기 추론 상태를 사용합니다.

무유실 기준에서 각 사례의 고정 수정 라벨 노드 중 하나 이상이 임계값을 엄격히 초과해야 합니다. 하나라도 충족하지 못하면 유실 비교를 시작하지 않고, 해당 탐지기가 이 가설을 검증하지 못했다는 결과로 기록합니다.

이 기준 실행에서 1회 소요 시간과 디스크 사용량을 측정합니다. 측정값으로 723회의 총 소요를 추정하고, 확보 가능한 시간을 넘으면 [실험 설계](EXPERIMENT_DESIGN.md)의 축소 규칙을 단계 순서대로만 적용합니다. 어느 단계까지 적용했는지 실행 기록의 `reduction_step_applied`에 남깁니다.

## 6. 실행 결과를 기록으로 변환

탐지기가 노드별 이상 점수를 내면 아래 도구가 사례 판정과 라벨 노드 재현율을 계산해 실행 기록을 만듭니다. `--labels`에는 완전한 무유실 입력에서 고정한 정답 노드 집합을 넣습니다.

```powershell
python scripts/score_run.py --predictions preds.jsonl --labels frozen/scenario-1.json --threshold THRESHOLD --run-id scenario-1-random-10-seed-0 --case scenario-1 --host SysClient0201 --pattern random --requested-rate 0.10 --seed 0 --input-sha256 SOURCE_SHA256 --mask-sha256 MASK_SHA256 --selection-start START --selection-end END --deleted-count K --detector-commit ae1e9fd42604c769c01b2eaed6fb7f65e27f3cac --checkpoint-sha256 CKPT --started-at-utc STARTED --output records/scenario-1-random-10-seed-0.json
```

분모는 고정한 정답 노드 수이며 이 실행에서 살아남은 노드 수가 아닙니다. 유실로 사라진 정답 노드는 미탐지로 셉니다. 무유실 기준 실행은 `--pattern baseline`을 쓰고 `--seed`와 `--mask-sha256`을 넣지 않습니다.

## 7. 결과 보관과 재확인

각 실행은 [실행 기록 계약](../config/run_record_schema.json)의 필드를 갖춘 JSON 한 줄로 남깁니다. 입력·코드·가중치 해시, 사례·구간 위치, 시드, 유실률, 삭제 수, 탐지 여부, 탐지한 라벨 노드 수와 총수, 시작·종료 시각, 종료 상태가 필수입니다. 실패한 실행은 `exit_status`를 `failed`로 기록하고 삭제하지 않습니다.

집계는 실행 기록만 입력으로 받습니다. 계산식은 결과 확인 전에 고정했으며 [분석 계획](ANALYSIS_PLAN.md)과 같습니다.

```powershell
python scripts/aggregate_results.py --records results/runs.jsonl --output results/summary.json
```

집계 도구는 계약을 위반한 기록을 거부하고, 실패한 실행을 평균에서 제외하며, 주비교 유실률에서 사례 탐지율이 포화됐는지와 그때 어느 지표로 결론을 내리는지를 함께 출력합니다.

코드와 문서의 짧은 확인은 다음 명령으로 수행합니다.

```powershell
python -W error::ResourceWarning -m unittest discover -s tests -v
python scripts/loss_masks.py --help
python scripts/apply_loss_mask.py --help
python scripts/window_positions.py --help
python scripts/score_run.py --help
python scripts/aggregate_results.py --help
```

첫 명령은 유실 마스크·마스크 적용·구간 산출·겹침 측정·채점·집계·고정 입력 검증을 실행합니다. 나머지는 실행 인자를 확인합니다. 실제 로그가 확보된 뒤에는 선택 로그 manifest와 변형 manifest의 SHA-256·이벤트 수를 함께 대조합니다.
