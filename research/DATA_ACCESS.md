# OpTC 데이터 접근 확인 — 2026-09-10

## 확인 결과

공식 Google Drive 원본은 기존 h051 파일 외에 h201 공격 첫날 파일 2개와 h501 공격일 파일 2개를 추가 확인했다. 모두 HTTP 200이지만 본문은 `Quota exceeded` HTML이었다. 전체 원본 배포가 영구적으로 불가능하다는 결론은 내리지 않는다.

Inria 수정본은 실제 바이트 수신과 JSON 파싱에 성공했다. 원본 OpTC와 구분하는 대체 자료이며 아직 주실험 데이터로 확정하지 않았다.

| 자료 | 결과 | 근거 |
| --- | --- | --- |
| 공식 원본 추가 4개 | 할당량 초과 | [응답 manifest](source_checks/20260910T005600958901Z/manifest.json) |
| Inria 파일 목록 | 공개 파일 11개, 파일 ID·크기·MD5 확보 | [API 응답](source_checks/20260910T005508288734Z/inria_metadata.sample) |
| Inria README | 1,639바이트 다운로드, 제공 MD5와 일치 | [README](source_checks/20260910T005600958901Z/inria_readme_curl.sample) |
| Inria 9월 25일 TAR | Range 요청으로 262,144바이트 수신, TAR 헤더 확인 | [표본 검사 결과](source_checks/20260910T005600958901Z/inria_schema_check.json) |
| 실제 eCAR 표본 | SysClient0269 이벤트 1,837건 JSON 파싱 | [표본 JSONL](source_checks/20260910T005600958901Z/inria_events_prefix.jsonl) |

Python urllib는 Inria 파일 서버의 인증서 체인 검증에 실패했다. Windows Schannel을 사용하는 curl은 인증서 검증을 유지한 상태로 성공했다. `--insecure` 또는 인증서 검증 해제는 사용하지 않았다. 최초 Python 실패와 이후 curl 성공을 구분해서 해석한다.

표본은 TAR의 첫 파일 일부를 읽은 것이다. 완전한 gzip CRC나 TAR 전체 MD5는 검증하지 못했다. 압축 내부 파일 전체 크기는 139,309,660바이트이며 이를 모두 받은 것이 아니다. 공격 호스트 표본이 아니고 탐지 결과도 아니다.

## 원본과 수정본의 차이

[배포 README](https://entrepot.recherche.data.gouv.fr/api/access/datafile/717349)는 원본을 클라이언트·날짜별로 분리하고 timestamp 순으로 정렬한 후 수정 스크립트를 적용했다고 설명한다. TAR 안에는 호스트별 JSON gzip 파일이 있다.

[연구자 발표 자료](https://www.acsac.org/2025/workshops/cset/proceedings/Majorczyk-ANewHopeForDARPAOpTC-2025-12-08.pdf)의 결론은 actorID 불일치 수정과 호스트·네트워크 라벨링을 설명한다. 오류 수정은 provenance 연결 관계에 영향을 줄 수 있다. 발표 자료를 확인한 것이며 수정 알고리즘 전체와 코드까지 검증한 것은 아니다.

이번 유실 실험에 적용할 때는 다음을 지킨다.

- 원본과 수정본을 같은 입력으로 혼합하지 않는다. 수정본을 택하면 가설·방법에 버전을 명시하고 무유실 기준부터 해당 버전으로 다시 만든다.
- 배포자가 전체 사건을 참고해 수행한 사전 보정을 그대로 전제한 결과임을 명시한다. 추가 유실은 보정된 기준에서 발생시킨다.
- 삭제된 사건에서 유래한 속성을 탐지기에 남기지 않도록 유실 후 전처리 원칙은 유지한다.
- 수정본 라벨과 공식 정답의 대응을 확인한다. 접근 가능성만으로 라벨 신뢰성이나 가설의 지지를 주장하지 않는다.

## 실제 다운로드 경로

배포: https://entrepot.recherche.data.gouv.fr/dataset.xhtml?persistentId=doi:10.57745/UXCWOC

- README: `https://entrepot.recherche.data.gouv.fr/api/access/datafile/717349`
- 2019-09-25 TAR: `https://entrepot.recherche.data.gouv.fr/api/access/datafile/713576`
- TAR 전체 크기: 67,718,440,960바이트 (약 67.7GB 또는 63.1GiB).
- TAR 전체 MD5: `f92af2a8236f0b53f29b6f213f130cf4`.
- README MD5: `14224bcfaa98642b9021095f88a8e9d5` — 로컬 파일과 일치 확인.

Windows에서 검증한 소량 다운로드 명령(출력 경로는 새 파일로 지정):

```powershell
curl.exe --fail --location --max-time 45 --range 0-262143 --max-filesize 262144 --output sample.tar.part https://entrepot.recherche.data.gouv.fr/api/access/datafile/713576
```

전체 파일 다운로드나 공격 호스트 파일 추출은 아직 수행하지 않았다. 부분 요청은 성공했으므로 다음 확보 단계에서 TAR 헤더를 따라 필요한 호스트 파일을 선택적으로 받는 방식을 검토할 수 있다. 임의 구간 요청·멤버 전체 수신·gzip 무결성을 추가 검증해야 한다. 전체를 받는 경우 별도 공간 확보와 제공 MD5 대조가 필요하다.

## 다음 단계

1. 수정 알고리즘과 라벨 생성 코드 검토, 연구에 사용할 버전 고정.
2. 공격 호스트 051·201·501 및 필요한 정상 날짜 파일 목록 확정.
3. 선택 파일의 완전한 수신·gzip 무결성 확인과 SHA-256 기록.
4. 실제 공격 정답 대응과 무유실 탐지 기준 실행.

후속 확인에서 공격 호스트 201·501·051의 정확한 TAR 멤버 위치와 크기를 모두 찾았다. 세 멤버 전체의 선택 다운로드는 서버 HTTP 503으로 실패했다. 수정·라벨 코드와 적용 조건 검토 결과는 [수정·라벨 검토](LABEL_AND_CORRECTION_REVIEW.md)에 기록했다.

데이터 다운로드 경로 확인은 완료했으나 카드 3의 실험 실행 완료를 뜻하지 않는다.
