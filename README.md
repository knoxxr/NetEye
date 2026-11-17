# NetEye OT 보안 모니터

NetEye는 Nozomi Guardian, Claroty CTD와 같은 계열의 **수동형(passive) OT/ICS 네트워크 보안 모니터**입니다.
스위치 미러 포트(SPAN/TAP)로 복제된 트래픽이나 PCAP 파일을 읽어 다음을 수행합니다.

- **산업용 프로토콜 DPI**: 프로토콜별 기능 코드와 명령을 해석합니다.
- **자산 식별**: 프로토콜 응답에서 벤더, 모델·주문번호, 펌웨어, 시리얼, 스테이션 이름을 추출하고, 자산의
  역할(PLC, RTU/IED, 엔지니어링 워크스테이션, HMI)을 추정합니다.
- **자산 정보 입력**: 자산 상세의 **정보 편집**(운영자 이상)에서 표시 이름, 장비 유형, 벤더, 모델, 펌웨어, 운영체제,
  위치, 담당자, 중요도(낮음~심각), 메모를 입력합니다. 입력한 값이 자동 식별 값보다 우선하고, 자동 값은 "자동 식별: …"로
  함께 보입니다(비우면 자동 값으로 돌아감). 벤더·모델·펌웨어는 취약점 대조에도 쓰여, 트래픽으로 식별되지 않는 장비도
  모델명(예: `S7-300`, `ControlLogix 5570`, `M340`)만 넣으면 해당 권고문과 대조됩니다. 표시 이름은 맵·목록의 이름이
  되고, 위치·담당자·메모까지 검색됩니다. 수정자와 시각이 자산에 남고 감사 로그에도 기록됩니다
  (`POST /api/assets/{id}/manual`).
- **컴퓨터 이름·운영체제**: PC·서버가 스스로 내보내는 패킷만으로 추정합니다(능동 질의 없음).

  | 출처 | 얻는 정보 |
  |---|---|
  | DHCP 요청 | 컴퓨터 이름(옵션 12), OS(벤더 클래스 `MSFT 5.0`, `android-dhcp-13`, `dhcpcd …:Linux-6.1`, Apple 옵션 순서) |
  | NetBIOS 이름 등록(UDP 137)·브라우저 알림(UDP 138) | Windows 컴퓨터 이름, Windows 버전(10.0 → Windows 10/11 등) |
  | mDNS(UDP 5353)·LLMNR(UDP 5355) 응답 | 자기 주소에 대한 이름(`*.local`) |
  | HTTP User-Agent, SSH 배너, SSDP SERVER·USER-AGENT | OS와 버전(`Windows NT 10.0`, `Ubuntu`, `Android 13`, `iPhone OS 17_1` 등) |
  | TCP SYN·SYN-ACK 지문(내부 주소만) | 초기 TTL·윈도·옵션 순서로 OS 계열(Windows / Linux / macOS / 임베디드 RTOS) |

  출처마다 신뢰도가 있어 더 확실한 출처가 약한 추정을 덮어씁니다. 자산 상세에 "운영체제 (수동 추정 75%)"와 근거가
  표시되고, 맵에는 컴퓨터 이름이 IP 대신 노드 이름으로 나옵니다. 인터넷 서버의 TCP 지문은 부하 분산 장비가 바꿔
  놓아 믿을 수 없으므로 쓰지 않습니다. CPU 모델·사용률처럼 네트워크에 흘러나오지 않는 정보는 얻을 수 없습니다.
- **통신 맵**: 클라이언트 → 서버 관계와 각 통신에서 쓰인 명령(읽기, 쓰기, 제어, 프로그램 변경)을 기록합니다.
- **실시간 네트워크 맵**: 자산 사이를 오가는 패킷을 점으로 흘려 보여 줍니다(요청은 청록, 응답·보고는 파랑, 경고가 걸린
  통신은 빨강). 패킷을 받은 노드에는 파동이 일고, 많이 오가는 통신은 선이 굵어집니다. 휠·버튼으로 확대/축소, 드래그로
  이동, 노드를 끌어 위치 고정(더블클릭으로 해제), 빈 곳 더블클릭으로 전체 보기를 합니다. Canvas로 그려 자산 1,500개·
  통신 2,200개에서도 초당 50프레임 안팎을 유지하며, 바뀌지 않은 스냅샷은 서버가 다시 보내지 않습니다.
  - **트래픽 양 표시**: 통신선의 색·굵기가 초당 패킷 수에 따라 바뀝니다(1 미만 파랑, 1–10 청록, 10–100 노랑,
    100 이상 주황). 바쁜 통신일수록 패킷 점이 크고 빠르며, 노드 크기는 누적 패킷 수(로그 비율)를 나타냅니다.
  - **배치**: *서브넷 그룹*(기본)은 /24 대역마다 영역을 나눠 통신하는 장비는 위쪽에 자유 배치하고, 통신 없이 ARP로만
    보인 장비는 아래쪽에 IP 순 격자로 정렬합니다. *Purdue 계층*은 외부망(L4–5), 운영·IT망(L3), 감시·제어(L2),
    제어기·현장 장비(L0–1) 층으로 나눕니다. *자유 배치*는 힘 기반 배치입니다.
  - **정리 옵션**: 공인 IP는 기본으로 "인터넷" 노드 하나로 묶고(클릭하면 펼침), 통신 없는 자산은 숨길 수 있습니다.
    통신 라벨은 선택한 자산의 통신이거나 충분히 확대했을 때만 보입니다.
  - **전체 화면**: 맵 오른쪽 위 ⛶ 버튼(Esc로 종료). 대시보드는 브라우저 너비를 꽉 채웁니다.
- **위협 경고**: PLC Stop/Start, 프로그램 다운로드/업로드, 장비 재시작, 설정 변경, 원격 제어 명령 등을
  탐지합니다. 같은 경고는 묶어서 횟수로 세고, 확인 처리할 수 있습니다.
- **베이스라인 이상 탐지**: 학습 모드에서 자산, 통신(프로토콜별 클라이언트 → 서버), 명령(통신별 기능 코드)을
  정상으로 기록하고, 탐지 모드에서 신규 자산·새로운 통신·새로운 명령을 경고합니다. 정상으로 확인된 이탈은
  클릭 한 번으로 베이스라인에 추가합니다.
- **공정 값 이상 탐지**: 쓰기 명령의 값(설정값, 코일, 태그)과 읽기 응답·자발 보고의 측정값(온도, 압력, 상태
  비트)을 레지스터·태그마다 학습해 **학습 범위를 벗어난 값,
  학습되지 않은 주소에 쓰기, 처음 보는 상태값**을 경고합니다. 스턱스넷처럼 설정값을 몰래 바꾸는 공격을 잡아냅니다.
- **통계적 이상 탐지**: 통신마다 분당 트래픽 양과 요청 주기를 학습해 **통신 중단, 트래픽 급증, 폴링 주기 변화**를
  잡아냅니다. 새 통신을 만들지 않는 공격이나 장비 고장도 놓치지 않습니다.
- **취약점 관리**: 자산의 벤더·모델·주문번호·펌웨어를 CISA ICS 권고문(CSAF)과 CISA KEV(실제 악용 확인)
  목록에 **오프라인으로** 대조해 자산별 위험도를 매깁니다.

센서는 Rust로 작성된 단일 실행 파일이며 코어 하나로 초당 약 230만 패킷을 처리합니다([성능](#성능) 참고).
패킷 내용(payload)은 저장하지 않습니다. 자산, 통신, 경고, 베이스라인, 계정, 감사 로그는
[BangDB](https://github.com/knoxxr/BangDB)(`data/neteye.bdb`)에 저장합니다([데이터베이스](#데이터베이스-bangdb) 참고).

## 지원 프로토콜

| 프로토콜 | 분석 수준 |
|---|---|
| Siemens S7comm (TCP 102) | 명령(Read/Write Var, PLC Stop, Download/Upload, `_INSE`·`_DELE`·`P_PROGRAM` 등 PI 서비스), SZL 0x0011의 주문번호·펌웨어, 비밀번호 전송 |
| Siemens S7comm-plus | 버전 식별, V1/V2 기능(Get/SetMultiVariables 등) |
| Modbus/TCP | 모든 기능 코드, 예외 응답, 진단(Force Listen Only 등), MEI 장비 식별 |
| Schneider UMAS (Modbus FC 90) | PLC Start/Stop, 프로그램 다운로드/업로드 |
| EtherNet/IP · CIP | ListIdentity·Get Attributes All 장비 식별, CIP 서비스(Reset/Start/Stop, Set Attribute), Logix Read/Write Tag(읽기·쓰기 값 포함), Multiple Service Packet(묶음 요청 개별 해석), Unconnected Send, Non-Volatile Storage 펌웨어 업데이트 |
| DNP3 | 응용 계층 기능 코드(Operate, Cold/Warm Restart, Stop Application, 파일 전송 등) |
| IEC 60870-5-104 | I/S/U 프레임, ASDU 형식과 전송 원인, 제어·설정값·Reset Process 명령 |
| IEC 61850 | GOOSE(gocbRef, stNum/sqNum, 시뮬레이션 플래그), Sampled Values, MMS 세션 탐지 |
| PROFINET | DCP Identify(스테이션 이름, 모델, 벤더, IP), DCP Set(IP·이름 변경, 공장 초기화), RT 주기 I/O |
| Mitsubishi SLMP/MC (3E 바이너리) | Remote RUN/STOP/RESET, 읽기/쓰기, CPU 모델 (내용 기반 탐지라 포트와 무관) |
| CC-Link IE (Ethertype 0x890F), CC-Link IE Field Basic | 탐지 |
| OPC UA | 메시지 종류, 보안 정책 None 사용 시 경고 |
| LLDP | 시스템 이름, 설명, 관리 IP |
| EtherCAT, POWERLINK, BACnet/IP, Omron FINS, HART-IP, CODESYS, GE SRTP 등 | Ethertype 또는 포트로 탐지 |

DeviceNet과 기존 CC-Link 필드버스는 이더넷이 아니라 CAN·RS-485 위에서 동작하므로 스위치 미러 포트에 나타나지
않습니다. 보려면 필드버스 탭이나 게이트웨이가 필요하고, 상위의 EtherNet/IP·CIP 트래픽으로 간접 관찰할 수 있습니다.

## 빌드와 실행

Rust 1.85 이상과 Go 1.22 이상이 필요합니다(Go는 BangDB 빌드용). C 컴파일러와 캡처 SDK는 필요 없습니다.

```powershell
python tools/build_bangdb.py          # 고정 버전 BangDB v0.7.73 -> sensor/target/release/bangdb.exe
cd sensor
cargo build --release
.\target\release\neteye.exe            # 리눅스: ./target/release/neteye
```

배포할 때는 `neteye`와 `bangdb`를 같은 폴더에 두고 `frontend/`를 함께 복사합니다.

`http://127.0.0.1:8000`을 열고 **PCAP 분석** 버튼으로 pcap·pcapng 파일을 올리면 됩니다. 실행 파일은
저장소나 실행 파일 옆의 `frontend/`를 찾습니다. 다른 위치에 두려면 `NETEYE_FRONTEND`를 설정하세요.

### 실시간 수동 캡처

센서 전용 인터페이스를 스위치 미러 포트에 연결하고, 캡처 드라이버(Windows는 Npcap, 리눅스는 `libpcap`
패키지)를 설치한 뒤 인터페이스를 지정합니다.

```powershell
.\target\release\neteye.exe interfaces          # 캡처 가능한 인터페이스 목록
$env:NETEYE_INTERFACE = "\Device\NPF_{...}"      # 리눅스: export NETEYE_INTERFACE=eth1
.\target\release\neteye.exe
```

캡처 라이브러리는 실행할 때 불러옵니다. 라이브러리가 없어도 센서는 실행되며 PCAP 분석만 가능하고, 이유는
대시보드에 표시됩니다. 캡처는 64MB 커널 버퍼를 쓰고 패킷을 묶음 단위로 엔진에 반영합니다.

### 명령줄

```powershell
neteye import capture.pcap [--db data\neteye.bdb] [--vulndb data\vulndb.json]   # 분석 후 요약 출력
neteye replay a.pcap --detect b.pcap                # a로 학습, b로 탐지 후 스냅숏 JSON 출력
neteye bench <pcap 파일 또는 폴더> --repeat 50       # 처리량 벤치마크
```

### 환경 변수

| 변수 | 기본값 | 설명 |
|---|---|---|
| `NETEYE_HOST` / `NETEYE_PORT` | `127.0.0.1` / `8000` | 대시보드·API 수신 주소 |
| `NETEYE_INTERFACE` | (없음) | 실시간 캡처 인터페이스 |
| `NETEYE_DB` | `data/neteye.bdb` | BangDB 데이터베이스 파일 (관리 모드) |
| `NETEYE_BANGDB_BIN` | `neteye` 옆, 그다음 `PATH` | 실행할 `bangdb` 실행 파일 |
| `NETEYE_BANGDB_URL` | (없음) | 직접 띄우지 않고 기존 BangDB HTTP API 사용 (예: `http://db01:18080`) |
| `NETEYE_BANGDB_TOKEN` / `NETEYE_BANGDB_USER` + `NETEYE_BANGDB_PASSWORD` | (없음) | `NETEYE_BANGDB_URL` 인증 정보: 서버의 `-password` 값, 또는 `users_file` 계정(`write` 역할, 테이블을 처음 만들 때는 `admin`) |
| `NETEYE_MAX_PCAP_MB` | 512 | 업로드 크기 제한 |
| `NETEYE_LEARNING_HOURS` | 0 | 새 데이터베이스의 초기 학습 기간(시간). 0이면 대시보드에서 수동으로 탐지 모드로 전환 |
| `NETEYE_VULNDB` | `data/vulndb.json` | 시작할 때 불러올 취약점 DB |
| `NETEYE_IPASN` | `data/ip2asn-v4.tsv.gz` | 인터넷 주소의 소유 조직(AS)·국가 DB. `python tools/ipasn_build.py`로 생성 |
| `NETEYE_BLOCKLIST` | `data/blocklist.txt` | 위협 인텔리전스 목록. `python tools/threatintel_build.py`로 생성 |
| `NETEYE_INTERNAL_NETS` | (없음) | 공인 주소 대역을 내부망으로 쓰는 현장의 내부 대역, 쉼표로 구분 (예: `166.161.0.0/16`) |
| `NETEYE_FRONTEND` | `frontend/` | 대시보드 파일 위치 |
| `NETEYE_COOKIE_SECURE` | 0 | TLS 뒤에 둘 때 1로 설정 (세션 쿠키를 HTTPS로만 전송) |
| `NETEYE_SYSLOG` | (없음) | SIEM 전송 대상, 쉼표로 구분: `udp://10.0.0.5:514,tcp://siem:601` (포트 생략 시 514) |
| `NETEYE_SYSLOG_FORMAT` | `cef` | `cef`(ArcSight Common Event Format) 또는 `json` |
| `NETEYE_SYSLOG_FACILITY` | 20 | syslog facility 번호 (20 = local4) |
| `NETEYE_ALLOWED_HOSTS` | (없음) | 대시보드 접속을 허용할 추가 호스트 이름·IP, 쉼표로 구분 (예: `sensor01.plant.local`). 루프백 이름은 항상 허용 |

## 베이스라인 운영

1. 새로 설치하면 **학습 모드**로 시작합니다. 정상 운전 기간(보통 1~2주, 정기 점검과 교대 근무 포함)의 트래픽을
   관측하거나, 정상 기간에 수집한 PCAP을 올립니다.
2. 대시보드에서 **탐지 모드 시작**을 누르면 그 시점까지 본 자산·통신·명령이 베이스라인으로 고정됩니다.
3. 그 뒤로 베이스라인에 없는 동작은 "이탈" 경고가 됩니다.
   - 신규 자산, 신규 외부(인터넷) 주소: 보통
   - 새로운 통신: 산업 프로토콜이면 높음, TCP/UDP 같은 일반 통신이면 낮음
   - 새로운 명령: 운전 상태 제어·프로그램·설정 변경·제어 명령은 높음, 쓰기·탐색·진단은 보통, 읽기는 낮음
4. 신규 장비 설치 같은 정상 변경은 경고의 **정상 등록**으로 베이스라인에 추가합니다. 통신을 등록하면 그 통신에서
   이미 관측된 명령도 함께 등록됩니다.

위험 명령에 대한 정책 경고는 학습 중에도 항상 발생하며, 정책 경고가 난 패킷에서는 이탈 경고를 중복으로 내지 않습니다.

### 공정 값 이상 탐지

쓰기 명령에서 대상 주소(포인트)와 값을 꺼내, 학습 모드 동안 포인트마다 최소·최대·평균·표준편차와 나온 값의
종류(최대 8개)를 학습합니다.

| 프로토콜 | 포인트 이름 예 | 해석하는 쓰기 |
|---|---|---|
| Modbus/TCP | `u1 HR16`(유닛 1 홀딩 레지스터 16), `u1 CO7`(코일 7) | FC5, FC6, FC15, FC16, FC23 |
| S7comm | `DB10.DBW4`, `DB1.DBD8`, `DB1.DBX0.3`, `MW10`, `Q0.0` | Write Var (BIT, BYTE, WORD, INT, DWORD, DINT, REAL) |
| EtherNet/IP · CIP | `Pump_Speed`, `Arr[3]` | Logix Write Tag (BOOL, SINT, INT, DINT, LINT, REAL, LREAL 등) |
| IEC 60870-5-104 | `CA7 IOA4001 C_SE_NC` | 단일·이중 명령, 단계 명령, 정규화·스케일·실수 설정값 (활성화 요청) |

| 경고 | 조건 | 심각도 |
|---|---|---|
| 공정 값 범위 이탈 | 연속값이 학습 범위(최소~최대)에 범위의 10% 여유를 더한 구간 밖. 학습 동안 값이 하나뿐이었다면 어떤 변경이든 경고 | 높음 |
| 학습되지 않은 상태 값 | 코일·BOOL·명령, 또는 학습 중 4가지 이하의 정수만 나온 포인트에 새 값이 쓰임 | 보통 |
| 학습되지 않은 주소에 쓰기 | 학습 중 한 번도 쓰이지 않은 레지스터·태그에 쓰기 (포인트마다 한 번) | 보통 |

- 판단에는 포인트마다 최소 3번의 학습된 쓰기가 필요합니다.
- 학습한 값은 BangDB에 저장되어 재시작 후에도 유지되고, **초기화 후 재학습**하면 지워집니다. 자산 상세의
  "공정 포인트 (쓰기 값)"에 마지막으로 쓴 값과 학습 범위·상태가 표시됩니다.
#### 측정값 (읽기 응답·자발 보고)

장비가 돌려주거나 보고하는 공정 측정값도 같은 방식으로 학습합니다.

- **Modbus FC1~4**: 응답에는 주소가 없으므로 **트랜잭션 ID로 요청과 짝지어** 레지스터·코일 주소를 되찾습니다
  (`u1 HR100`, `u1 IR3`, `u1 DI0`). 요청을 놓친 응답은 엉뚱한 주소에 붙이지 않고 버립니다.
- **S7 Read Var**: Job과 Ack_Data를 **PDU 참조 번호로 짝지어** 형식(BIT~REAL)대로 해석합니다(`DB10.DBD4`, `M10.2`).
- **IEC 104**: 단일·이중 포인트, 정규화·스케일·실수 측정값(시각 포함 여부 무관, 순차·개별 주소 방식 모두)을
  IOA와 함께 받습니다(`CA7 IOA3001 M_ME_NC`).
- **EtherNet/IP · CIP (Logix)**: 심볼 태그 Read Tag 응답을 형식(BOOL~LREAL)대로 해석합니다(`Tank_Level`, 배열은
  `Arr[0]`). HMI가 태그 여러 개를 한 번에 묻는 **Multiple Service Packet**은 묶인 요청을 하나씩 풀고 응답을
  순서대로 맞춥니다. 일부만 실패한 응답(상태 0x1E)에서도 성공한 값은 반영하고, 묶음 안의 Write Tag 값은 쓰기
  값으로 학습합니다. 요청·응답은 비연결형(SendRRData)이면 캡슐화 헤더의 **Sender Context**로, 연결형
  (SendUnitData)이면 **시퀀스 번호**로 짝짓습니다. 클래스 주소로 부르는 객체 전용 0x4C 서비스는 태그 값이 아니므로
  무시합니다.

| 경고 | 조건 | 심각도 |
|---|---|---|
| 측정값 범위 이탈 | 학습 범위 밖으로 범위의 25% 또는 표준편차의 3배(큰 쪽) 이상 벗어남 | 보통 |
| 측정 상태 미학습 값 | 상태형 포인트(상태 비트, 2~4가지 값)에 학습 중 없던 값 | 낮음 |

측정값은 자연스럽게 변하므로 쓰기 값보다 여유를 넓게 두고, 탐지 모드에서 처음 읽은 주소는 경고하지 않습니다.
자산 상세에는 포인트마다 "쓰기"·"측정" 표시가 붙습니다.

### 통계적 이상 탐지

학습 모드 동안 통신(클라이언트 → 서버, 프로토콜별)마다 **1분당 패킷 수**와 **요청 간격**의 평균·분산을 온라인
(Welford)으로 학습합니다. 탐지 모드에서는 학습한 정상 패턴에서 크게 벗어나면 "통계" 경고를 냅니다.

| 경고 | 조건 | 심각도 | 의심 상황 |
|---|---|---|---|
| 통신 중단 | 주기적으로 폴링되던 통신이 `max(주기 × 10, 30초)` 넘게 끊김 (끊길 때마다 한 번) | 높음 | 장비 고장, DoS, 케이블·스위치 장애 |
| 트래픽 급증 | 1분 패킷 수가 `평균 + 5 × 표준편차` 이상이면서 평균의 2배 + 10건 이상 | 보통 | 스캔, 플러딩, 비정상 반복 쓰기 |
| 폴링 주기 변화 | 1분 동안 평균 요청 간격이 학습값에서 `max(3 × 표준편차, 50%)` 넘게 벗어남 | 보통 | 중간자 장비, 설정 변경, 오동작 |

- 판단에는 최소 5분(분당 트래픽) 또는 요청 20건(주기)의 학습 데이터가 필요하며, 그보다 적게 학습된 통신은
  판단하지 않습니다. 통신 중단은 주기가 일정한(변동계수 0.5 이하) 통신에만 적용합니다.
- 시각은 패킷 타임스탬프를 기준으로 하므로 녹화된 PCAP 재생과 실시간 캡처가 같은 결과를 냅니다.
- 학습한 패턴은 통신과 함께 저장되어 재시작 후에도 유지되고, **초기화 후 재학습**하면 지워집니다. 자산 상세의
  통신 항목에 "학습: 요청 주기 1.0초 ±0ms · 분당 60건"처럼 표시됩니다.

API: `GET /api/baseline`, `POST /api/baseline/mode` (`{"mode": "learning"|"detecting", "hours": 24, "reset": false}`),
`POST /api/alerts/{id}/learn`, `POST /api/alerts/{id}/ack`

## 외부(인터넷) 통신 분석

센서는 내부망과 인터넷 사이의 대화를 따로 추적합니다. 누가 연결을 열었는지(TCP SYN), 어떤 서비스 포트인지,
방향(내부 → 인터넷 / 인터넷 → 내부)을 기록하고, 상대 주소가 누구인지와 의심 여부를 판단합니다. 외부 서비스에
아무것도 물어보지 않으며 모든 판단은 센서 안의 자료로 합니다.

**상대가 누구인지**

- **소유 조직**: 오프라인 IP→AS DB(iptoasn.com, 퍼블릭 도메인)로 AS 번호·조직·국가를 찾습니다. Google, Microsoft,
  AWS, Cloudflare, Akamai, Apple, NAVER, Kakao, KT, SK브로드밴드, LG U+ 등은 "잘 알려진 조직"으로 친숙한 이름을 붙입니다.
- **접속에 쓰인 이름**: DNS 응답, TLS ClientHello의 SNI, HTTP Host 헤더에서 그 주소로 접속할 때 쓴 도메인을 모읍니다
  (예: `chatgpt.com`). 자산 상세와 맵에 표시되고 검색됩니다.

```powershell
python tools/ipasn_build.py         # data/ip2asn-v4.tsv.gz (약 9MB, 46만 범위)
python tools/threatintel_build.py   # data/blocklist.txt (abuse.ch Feodo Tracker C2 + Spamhaus DROP)
```

현장 고유의 지표는 `data/blocklist_custom.txt`에 한 줄에 하나(`주소[/접두사] # 메모`)로 적으면 다시 만들 때 합쳐집니다.

**경고 (유형 "외부")**

| 경고 | 조건 | 심각도 |
|---|---|---|
| 위협 인텔리전스 목록 주소와 통신 | 상대 주소가 위협 목록에 있음 | 심각 |
| 산업 프로토콜의 인터넷 통신 | S7, Modbus, EtherNet/IP, DNP3, IEC 104, OPC UA, BACnet 등 산업 프로토콜 포트로 인터넷과 통신 | 심각 |
| 인터넷에서 내부 서비스로 접속 | 인터넷에서 연 연결을 내부가 받아들임(TCP SYN-ACK, 서비스 포트의 UDP 응답) | 높음, RDP·SMB·VNC·Telnet이나 OT 장비면 심각 |
| OT 장비의 인터넷 통신 | PLC·HMI·RTU 등 OT 장비(유형 또는 사용 프로토콜로 판단)가 인터넷으로 연결을 엶 | 높음 |

**외부 통신 표**: 인터넷 주소마다 조직·도메인, 내부 상대, 서비스(포트·방향), 패킷 수를 보여 주고 판단 수준
(위험 / 주의 / 참고 / 정상)과 사유를 붙여 의심스러운 순으로 정렬합니다. 사유에는 위 경고 조건 외에 "비표준 포트",
"DNS·SNI 이름 없이 직접 접속"(연결 시작을 본 경우에만), "조직 정보 없음"이 있습니다. 양쪽 모두 임시 포트인 UDP
(화상 통화, P2P)는 내부로의 접속으로 보지 않습니다.

## 데이터베이스 (BangDB)

NetEye는 모든 데이터를 Go로 작성된 임베디드 SQL 데이터베이스 [BangDB](https://github.com/knoxxr/BangDB)
(WAL, 크래시 복구, 스냅샷 읽기)에 저장합니다. 센서는 Rust라 cgo 툴체인 없이는 Go 코드를 링크할 수 없으므로,
BangDB가 다른 언어용으로 제공하는 HTTP/JSON API를 사용합니다.

- **관리 모드(기본)**: 센서가 시작할 때 `data/neteye.bdb`로 `bangdb`를 직접 실행합니다. BangDB는
  `127.0.0.1`의 무작위 빈 포트에서만 받으며, 센서는 실행할 때마다 새로 만든 무작위 토큰으로 인증합니다. 토큰은
  환경 변수로 전달하므로 프로세스 목록에 드러나지 않습니다. 센서가 종료되면 `bangdb`도 함께 멈춥니다. 비정상
  종료나 강제 종료 때도 Windows는 Job Object, 리눅스는 `PR_SET_PDEATHSIG`로 정리하므로, 남은 프로세스가 파일을
  잠가 두는 일이 없습니다.
- **외부 모드**: `NETEYE_BANGDB_URL`로 직접 운영하는 BangDB 서버를 지정합니다. 예를 들어 TLS·백업·복제를
  갖춘 중앙 서버를 쓸 수 있습니다(BangDB 문서 참고).
- **저장 방식**: 변경 사항은 5초마다 `/batch` 요청 한 번으로 저장합니다. BangDB는 배치를 한 트랜잭션으로
  처리하므로 저장은 전부 반영되거나 전혀 반영되지 않습니다. BangDB의 16MiB 요청 한도를 넘는 아주 큰 저장만
  나눠서 보냅니다.
- **내구성**: 센서(와 BangDB)를 정상 종료 없이 강제 종료한 뒤 다시 시작해, 자산·통신·경고·베이스라인·계정·감사
  로그가 모두 그대로 복구되는 것을 확인했습니다.
- BangDB 파일은 한 번에 한 프로세스만 열 수 있습니다. `neteye user …`는 센서를 멈춘 뒤 실행하거나, 계정은
  대시보드에서 관리하세요.

데이터를 직접 보려면 센서를 멈춘 상태에서 BangDB 도구(CLI, 웹 콘솔, BangDB Manager)로 같은 파일을 엽니다.
실행 중에 보려면 외부 모드의 BangDB 서버를 사용하세요.

**SQLite 버전에서 옮기기**: 테이블 구조는 같고, BangDB가 SQLite 덤프를 직접 가져옵니다.

```powershell
python tools/sqlite_to_bangdb.py data\neteye.db data\neteye.bdb
```

## SIEM 연동 (syslog)

경고와 감사 이벤트를 SIEM(Splunk, QRadar, ArcSight, Elastic, Sentinel 또는 일반 syslog 수집기)으로
RFC 5424 syslog 메시지(CEF 또는 JSON 형식)로 전송합니다.

```powershell
$env:NETEYE_SYSLOG = "tcp://siem.plant.local:601,udp://10.0.0.5:514"
$env:NETEYE_SYSLOG_FORMAT = "cef"
```

전송하는 이벤트:

| 시그니처 ID | 이벤트 | 심각도 (CEF 0–10) |
|---|---|---|
| `NE-POLICY-CONTROL`, `-PROGRAM`, `-CONFIG`, `-COMMAND`, `-WRITE`, … | 위험 명령 (PLC Stop, 프로그램 다운로드, 설정 변경 등) | 경고 심각도 기준: 심각 10 / 높음 8 / 보통 5 / 낮음 3 |
| `NE-BASELINE-COMM`, `NE-BASELINE-CMD`, `NE-ASSET-NEW` | 베이스라인 이탈 (새로운 통신, 새로운 명령, 신규 자산) | 위와 같음 |
| `NE-VULN-KEV`, `NE-VULN-CRITICAL`, `NE-FIRMWARE-CHANGE` | 취약 자산, 펌웨어 변경 | 위와 같음 |
| `NE-ANOMALY-SILENCE`, `NE-ANOMALY-VOLUME`, `NE-ANOMALY-INTERVAL` | 통계적 이상 (통신 중단, 트래픽 급증, 폴링 주기 변화) | 위와 같음 |
| `NE-PROCESS-RANGE`, `NE-PROCESS-STATE`, `NE-PROCESS-NEWPOINT` | 공정 값 이상 (범위 이탈, 새 상태값, 학습되지 않은 주소) | 위와 같음 |
| `NE-MEASURE-RANGE`, `NE-MEASURE-STATE` | 측정값 이상 (범위 이탈, 미학습 상태값) | 위와 같음 |
| `NE-EXT-THREAT`, `NE-EXT-ICS`, `NE-EXT-INBOUND`, `NE-EXT-OT` | 외부 통신 (위협 목록, 산업 프로토콜 인터넷 노출, 인터넷에서의 접속, OT 장비의 인터넷 통신) | 위와 같음 |
| `NE-AUDIT-LOGIN`, `-LOGIN-FAILED`, `-LOCKOUT`, `-DENIED`, `-CHANGE` | 로그인, 계정 잠금, 권한 부족으로 거부된 요청, 설정 변경 | 1 / 5 / 8 / 5 / 3 |

- 경고는 처음 발생할 때 한 번 보내고, 확인 처리한 뒤 다시 발생하면 한 번 더 보냅니다(`cs4=reopened`). 반복
  발생은 `cnt`에 횟수로 담기며 하나하나 다시 보내지 않습니다.
- CEF 필드: `rt`(발생 시각, epoch ms), `src`/`dst`, `smac`/`dmac`, `app`(프로토콜), `act`(명령),
  `cat`(분류), `cnt`, `externalId`(경고 ID), `suser`, `outcome`, `cs1`=탐지 방식(policy/baseline/anomaly),
  `cs2`/`cs3`=출발지·목적지 장비(유형, 벤더, 모델, 펌웨어), `cs5`=상세(JSON), `msg`.
- 전송 대상마다 별도의 전송 스레드와 최대 1만 건짜리 대기열이 있어, SIEM이 느리거나 응답하지 않아도 패킷 처리나
  다른 대상이 영향을 받지 않습니다. TCP는 1~30초 간격으로 재접속하며 대기 중이던 이벤트를 다시 보냅니다.
  대기열이 차면 가장 오래된 이벤트부터 버리고 그 수를 셉니다. **사용자 및 감사 로그** 패널과
  `GET /api/integrations`에서 대상별 연결 상태, 전송·대기·유실 건수, 마지막 오류를 볼 수 있습니다.
- 전달이 중요하면 TCP를 쓰세요. UDP는 수신 확인이 없어 SIEM이 꺼져 있는 동안 보낸 이벤트는 사라집니다. TCP도
  운영체제가 쓰기를 받은 직후 연결이 끊기면 그 사이의 이벤트가 유실될 수 있습니다. TLS syslog와 RELP는 아직
  지원하지 않습니다.

## 계정과 보안

대시보드와 API는 로그인해야 쓸 수 있으며, 역할 세 가지로 권한을 나눕니다.

| 역할 | 할 수 있는 일 |
|---|---|
| 조회자 | 자산, 경고, 베이스라인 상태, 취약점 보기 (읽기 전용) |
| 운영자 | 조회자 권한 + 경고 확인, 이탈을 정상으로 등록, PCAP 분석 |
| 관리자 | 운영자 권한 + 학습/탐지 모드 전환, 취약점 DB 교체, 사용자 관리, 감사 로그 보기 |

**최초 실행**: 계정이 하나도 없으면 무작위 비밀번호로 `admin` 계정을 만들어 콘솔에 출력하고
`data/initial-admin-password.txt`에도 저장합니다. 첫 로그인 때 비밀번호를 반드시 바꿔야 하며, 바꾸면 파일은
삭제됩니다. 관리자가 만들었거나 비밀번호를 재설정한 계정도 다음 로그인 때 비밀번호를 바꿔야 합니다.

**콘솔에서 계정 관리** (서버를 멈춘 상태에서 실행):

```powershell
neteye user list
neteye user add alice operator        # 비밀번호는 NETEYE_PASSWORD 환경 변수나 표준 입력에서 읽음
neteye user passwd alice
neteye user role alice admin
neteye user del alice
```

**보호 방식**:

- 비밀번호는 Argon2id(솔트 적용, 메모리 집약형)로 해시합니다. 10자 이상이어야 하고 사용자 이름과 달라야 합니다.
- 세션은 `HttpOnly; SameSite=Strict` 쿠키에 담긴 256비트 무작위 토큰입니다. 8시간 동안 사용하지 않거나 총
  24시간이 지나면 만료됩니다. 로그아웃, 비밀번호 변경, 역할 변경, 계정 삭제 시 해당 사용자의 세션은 즉시 끝나고
  열려 있는 실시간 WebSocket 연결도 닫힙니다. 센서 앞에 TLS를 둘 때는 `NETEYE_COOKIE_SECURE=1`을 설정하세요.
- 로그인을 5회 연속 실패하면 계정이 5분간 잠깁니다. 없는 계정도 같은 Argon2 연산을 거쳐 같은 응답을 받으므로,
  로그인 시도로 계정 존재 여부를 알아낼 수 없습니다.
- 권한은 기본 거부 방식입니다. 따로 정하지 않은 경로는 모두 관리자 전용이며, 마지막 관리자는 삭제하거나 권한을
  낮출 수 없습니다.
- 감사 로그는 로그인(성공·실패·잠금), 상태를 바꾸는 모든 요청, 권한 부족으로 거부된 모든 요청을 사용자·접속 IP·
  결과와 함께 기록합니다.
- 허용된 `Host` 이름으로 온 요청에만 응답해 DNS 리바인딩을 막습니다. `Origin`이 다른 사이트인 요청은 거부해
  CSRF와 크로스 사이트 WebSocket 탈취를 막습니다.
- API 응답은 `Cache-Control: no-store`이고, 정적 파일은 매번 서버에 재검증하므로 업그레이드 후 예전
  JavaScript·CSS가 쓰이는 일이 없습니다. 모든 응답에 `nosniff`, `X-Frame-Options: DENY`, `no-referrer`
  헤더를 붙입니다.

센서 자체는 HTTP로만 제공합니다. 원격에서 접속하려면 TLS 리버스 프록시를 앞에 두고 `NETEYE_ALLOWED_HOSTS`와
`NETEYE_COOKIE_SECURE=1`을 설정하세요.

API: `POST /api/login`, `POST /api/logout`, `GET /api/session`, `POST /api/password`,
`GET|POST /api/users`, `POST|DELETE /api/users/{name}`, `GET /api/audit`

## 취약점 데이터베이스

센서는 대개 인터넷과 분리된 망에 있으므로, 상용 OT 모니터가 위협 인텔리전스를 업데이트하는 것과 같은 방식으로
인터넷 PC에서 DB를 만든 뒤 옮깁니다.

```powershell
# 인터넷이 되는 PC에서 실행 (약 12MB 다운로드, 몇 초 안에 생성)
# Python 3 표준 라이브러리만 사용하므로 설치할 패키지가 없음
python tools/vulndb_build.py --fetch -o vulndb.json
# 오프라인 대안: python tools/vulndb_build.py --csaf-tar CSAF-develop.tar.gz --kev kev.json -o vulndb.json
```

만든 파일을 센서의 `data/vulndb.json`에 복사하거나, 대시보드의 **취약점 DB 업로드** 버튼(`POST /api/vulndb`)으로
올립니다. DB를 불러오는 즉시 모든 자산을 다시 대조하고, 자산의 식별 정보나 펌웨어가 바뀔 때마다 다시 대조합니다.

매칭은 근거의 강도에 따라 세 단계로 나눕니다.

| 단계 | 의미 |
|---|---|
| 확정 | 주문번호·카탈로그 번호가 권고문과 일치하고 펌웨어가 영향 범위 안 |
| 유력 | 제품군(예: S7-300, ControlLogix 5570)이 일치하고 펌웨어가 영향 범위 안 |
| 가능 | 제품은 맞지만 펌웨어를 모르거나 권고문의 버전 표현을 해석할 수 없음 |

`vers:intdot/<3.2.17`, `<V3.2.16`, `<V3.X.14`, `<= 3.2.12`, `20-33`, `V16 Update 5` 같은 버전 표현을
해석합니다. 자산 위험도는 권고문 CVSS에 매칭 단계 가중치를 곱하고, CVE가 KEV에 있으면 1.5를 더합니다(최대 10).
KEV CVE에 확정·유력으로 매칭되면 심각 경고, CVSS 9 이상에 확정으로 매칭되면 높음 경고를 냅니다.

API: `GET /api/vulndb`, `POST /api/vulndb`, `GET /api/vulns`

## 성능

Intel Core i7-1360P 노트북에서 실제 ICS 캡처 16개(S7, Modbus, EtherNet/IP, DNP3, IEC 104, EtherCAT,
POWERLINK 등, 프레임 평균 218바이트)를 메모리에서 재생해 측정했습니다. `neteye bench`로 다시 측정할 수 있습니다.

| 단계 | 이전 Python 버전 | Rust 센서 | 향상 |
|---|---|---|---|
| 디코드 | 63 kpps | 90,000+ kpps | 1,000배 이상 |
| 디코드 + 프로토콜 DPI, 1코어 | 97 kpps | 5,700 kpps | 59배 |
| 엔진 전체(자산, 통신, 베이스라인, 경고), 1코어 | 9.7 kpps (17 Mbps) | 1,400 kpps (2.5 Gbps) | 145배 |
| 엔진 전체, 펌웨어 전송 캡처 제외 | | 2,000 kpps | |
| 엔진 전체, S7 주기 읽기 캡처 (응답마다 측정값 다수) | | 1,270 kpps | |
| 디코드 + DPI, 16스레드 | 불가 (GIL) | 33,000 kpps | |
| 194MB / 83만 프레임 PCAP 가져오기 | 약 37초 | 0.40초 | 93배 |

측정 코퍼스의 31%는 PLC 펌웨어 전송 캡처(EIP-FirmwareChange)이며, 이 패킷은 모두 "CIP 펌웨어 업데이트" 심각 경고를
일으킵니다. 이 캡처를 빼면 엔진은 코어 하나로 초당 약 200만 패킷을 처리합니다. 폴링 응답에 담긴 측정값을 하나하나
판단하므로 값이 많은 S7 주기 읽기 트래픽에서는 초당 약 127만 패킷입니다. 최소 크기 프레임 기준 1Gbps 미러
포트는 초당 약 149만 패킷이므로, 모든 패킷이 공격 신호인 극단적 상황이 아니면 코어 하나로 회선 속도를 처리합니다.
취약점 DB 전체를 불러온 상태에서 센서 프로세스 메모리는 약 50MB입니다.

### Rust를 선택한 이유

센서는 공장망의 신뢰할 수 없는 트래픽을 회선 속도로 파싱해야 하므로 다음 네 가지가 필요했습니다.

- **가비지 컬렉션 정지가 없을 것**: GC로 멈추는 동안 캡처 버퍼가 넘쳐 패킷을 잃을 수 있어 Go·Java는 캡처
  경로에 맞지 않습니다.
- **파서의 메모리 안전성**: C/C++ 파서의 범위 밖 읽기 하나가 보안 센서 자체에 대한 원격 공격 경로가 됩니다.
  Suricata도 같은 이유로 파서를 Rust로 옮겼습니다.
- **실제 멀티코어 확장**: CPython은 GIL 때문에 Python 버전이 코어 하나에 묶였습니다.
- **단일 실행 파일**: 센서 장비와 폐쇄망에 배포하기 쉽습니다.

### 빠른 이유

- 패킷 바이트를 복사하지 않고 그대로 파싱합니다. IPv4 주소는 `u32`, MAC은 `u64`, 시각은 정수 밀리초입니다.
- 프로토콜·명령·역할·근거 이름은 한 번만 등록하고 번호로 다루므로, 평상시에는 패킷당 메모리 할당이 없습니다.
  경고 상세 정보도 실제로 경고가 날 때까지 숫자로 둡니다.
- 대시보드 스냅숏은 캡처 경로 밖에서 1초에 최대 한 번 만들어 모든 WebSocket 접속자가 공유합니다. 실시간
  캡처는 패킷을 묶어 한 번의 잠금으로 엔진에 반영합니다.

## 구조

```
sensor/                  Rust 센서 (제품 본체)
  src/decode.rs          이더넷/VLAN/IPv4/TCP/UDP/ARP 제로카피 디코더
  src/dissect/           프로토콜 DPI (modbus, iso_tsap = S7/MMS, enip, power = DNP3/104, layer2, misc)
  src/engine.rs          자산 식별, MAC↔IP 병합, 통신, 경고, 스냅숏
  src/baseline.rs        학습/탐지 모드와 자산·통신·명령 베이스라인
  src/profile.rs         통신별 통계 프로파일(분당 트래픽, 요청 주기)과 포인트별 공정 값 학습·이상 판단
  src/vulns.rs           취약점 매칭 (버전 범위, 제품군, 위험도)
  src/storage.rs         BangDB HTTP API를 통한 저장 (관리 모드 자식 프로세스 또는 외부 서버)
  src/siem.rs            syslog(RFC 5424) 전송, CEF/JSON, UDP/TCP, 대상별 대기열
  src/pcap.rs            pcap/pcapng 스트리밍 리더
  src/live.rs            libpcap/Npcap 실시간 캡처 (실행 시 로드)
  src/api.rs             HTTP API, WebSocket, 대시보드 정적 파일 (axum)
frontend/                대시보드 (API 규약은 이전과 동일)
tools/vulndb_build.py    CISA CSAF 권고문과 KEV로 vulndb.json 생성 (인터넷 PC에서 실행)
tools/build_bangdb.py    고정 버전 BangDB 서버를 센서 옆에 빌드
tools/sqlite_to_bangdb.py  이전 SQLite 버전의 데이터베이스를 BangDB로 이전
tools/differential.py    Rust 센서가 기준 엔진과 같은 결과를 내는지 검증
legacy/python/           이전 Python 구현 (차분 검증 기준으로 보관)
```

REST/WebSocket API와 대시보드는 이전과 같습니다. Python 버전을 포함한 이전 버전의 데이터는
`tools/sqlite_to_bangdb.py`로 BangDB에 옮깁니다.

## 검증

```powershell
cd sensor; cargo test --release                       # 테스트 79개: 동작, 요청 검사, 계정, BangDB 저장, SIEM, 통계·공정 값·측정값 이상 탐지
                                                      # (저장 테스트는 실제 인메모리 bangdb를 띄우므로 먼저 빌드 필요)
python tools/differential.py <pcap 폴더> --vulndb vulndb.json   # Rust와 기준 엔진을 필드 단위로 비교
```

차분 검증은 같은 캡처를 두 구현에 넣고 모든 자산 필드, 통신, 명령 횟수, 경고, 베이스라인 수, 취약점 매칭을
비교합니다. ICS-pcap 공개 캡처 16개와 학습→탐지, 취약점 시나리오까지 22개 시나리오가 모두 일치합니다.
(통계 이상 경고는 기준 엔진에 없는 기능이라 비교에서 제외합니다.)
레거시 테스트는 `cd legacy/python; python -m unittest discover -s backend/tests`로 그대로 실행됩니다.

## 알려진 제약

- 외부 통신 추적은 메모리에만 있어 센서를 다시 시작하면 새로 쌓입니다(경고와 자산의 도메인 이름은 저장됨).
  암호화된 DNS(DoH)나 TLS ECH를 쓰면 접속 이름을 알 수 없습니다. 조직 DB와 위협 목록은 도구로 새로 받아야 갱신됩니다.
- 공정 포인트는 최대 10만 개까지 학습합니다. 가득 차면 새 주소는 저장하지 않지만 그 주소로의 쓰기는 계속 경고하고,
  "공정 포인트 추적 한도 도달" 경고를 냅니다. 학습되지 않은 주소 쓰기는 같은 출발지·목적지 쌍마다 10분에 20건까지 개별
  경고, 이후는 요약 경고(심각도 높음) 하나에 주소 목록(최대 200개, 나머지는 개수)과 횟수로 모입니다.
- 로그인은 (계정, 접속 주소) 단위로 5회 실패 시 5분 잠깁니다. 한 계정에 15분간 20회 넘게 실패하면 5분간 그 계정에
  이전에 로그인한 적 있는 주소에서만 시도할 수 있습니다. IPv6는 /64 단위로 셉니다.
- 운영체제는 수동 추정입니다. 대부분 계열(Windows 10/11, Linux 등) 수준이고, 정확한 버전은 배너·User-Agent처럼
  장비가 직접 밝힐 때만 나옵니다. 컴퓨터 이름은 DHCP·NetBIOS·mDNS·LLMNR 패킷이 보일 때만 얻습니다.
- TCP 재조립이 없습니다. 여러 세그먼트로 나뉜 PDU는 첫 세그먼트만 분석합니다.
- S7comm-plus V3(최신 펌웨어의 S7-1200/1500)는 암호화·무결성 보호가 되어 있어 탐지와 세션 정보만 얻을 수 있습니다.
- 측정값은 Modbus·S7·IEC 104·CIP(Logix 심볼 태그)만 봅니다. DNP3 아날로그 입력·출력, Read Tag Fragmented(0x52),
  구조체·문자열 태그, 인스턴스 ID로 부르는 태그(심볼 인스턴스 주소)는 아직 해석하지 않으며, 값의
  변화율(급격한 변화)도 학습하지 않습니다.
  요일·교대 근무처럼 시간대별로 달라지는 패턴도 하나의 범위·평균으로 학습합니다.
- 취약점 매칭은 NetEye가 추출한 식별 정보만큼만 정확합니다. 벤더나 모델이 없는 자산(예: 포트로만 본 자산)은
  매칭되지 않습니다. 제품군 규칙은 현재 Siemens, Rockwell, Schneider, Mitsubishi 컨트롤러만 다룹니다.
- Siemens는 권고문을 갱신판으로 다시 발행하므로 같은 취약점이 여러 권고문 ID로 나타날 수 있습니다.
- 통합 인증(LDAP·Active Directory)과 다중 인증(MFA)은 아직 없습니다.
- SIEM 전송은 UDP·TCP 일반 syslog만 지원합니다. TLS(RFC 5425), RELP, 웹훅, Splunk HEC는 아직 없습니다.
- 개발 PC에 Npcap이 없어 실시간 캡처는 아직 실제로 실행해 보지 못했습니다. 캡처 경로는 표준 libpcap API
  (`pcap_create`, `pcap_activate`, `pcap_next_ex`)를 사용하며, 성능 측정은 PCAP 가져오기로만 했습니다.
- 초당 약 200만 패킷(10Gbps급)을 넘으려면 AF_PACKET fanout 등으로 엔진을 코어별로 나눠야 합니다. DPI는 이미
  여러 스레드로 확장됩니다.
