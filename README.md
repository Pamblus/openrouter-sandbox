# openrouter-sandbox
Deep technical teardown of the OpenRouter sandbox: Cloudflare Containers (cloudchamber) internals, the unauthenticated in-VM Bun HTTP API, WebSocket RPC, VSOCK services, SUID ccsh, and the full endpoint catalog — reverse-engineered from a live running instance.

# Автор: Pamblus
# OpenRouter Sandbox — полный технический разбор

> Сводный документ на основе прямого исследования работающего инстанса песочницы OpenRouter (`openrouter:shell` / `openrouter:bash`).
> Версия песочницы на момент исследования: `SANDBOX_VERSION=0.12.9`
> Дата: 2026-10-16 — 2026-10-18
> Контейнер: `container_id: termux-box`

---

## Содержание

1. [TL;DR](#1-tldr)
2. [Архитектура](#2-архитектура)
3. [Права и изоляция](#3-права-и-изоляция)
4. [Файловая система](#4-файловая-система)
5. [Сеть](#5-сеть)
6. [HTTP API песочницы](#6-http-api-песочницы)
7. [WebSocket RPC](#7-websocket-rpc)
8. [Сервисы Bun-сервера (DI)](#8-сервисы-bun-сервера-di)
9. [Переменные окружения](#9-переменные-окружения)
10. [Init-процесс (Rust)](#10-init-процесс-rust)
11. [Dropbear SSH / ccsh](#11-dropbear-ssh--ccsh)
12. [Внешний OpenRouter API](#12-внешний-openrouter-api)
13. [Что установлено в образе](#13-что-установлено-в-образе)
14. [Сводка: что работает / что нет](#14-сводка-что-работает--что-нет)
15. [Ошибки и логи](#15-ошибки-и-логи-для-отладки)
16. [Непроверенное и потенциальные направления](#16-непроверенное-и-потенциальные-направления)
17. [Практическая шпаргалка](#17-практическая-шпаргалка)
18. [Карта сервисов](#18-карта-сервисов)
19. [Открытые вопросы](#19-открытые-вопросы--куда-копать-дальше)

---

## 1. TL;DR

Песочница OpenRouter — это одноразовая Linux-microVM на инфраструктуре **Cloudflare Containers** (Firecracker-подобный гипервизор `cloudchamber`), в которой у нас root с полным набором capabilities и отключённым seccomp. Внутри VM крутится HTTP/WebSocket-сервер на Bun (`10.0.0.1:3000`) **без авторизации**, через который удобнее и быстрее работать с VM напрямую (shell, файлы, процессы, Python-интерпретатор), чем через модель-ретранслятор. Исходящий интернет из VM заблокирован (egress-прокси по allowlist, пустой по умолчанию), SSH отключён без ключей, VSOCK из Python недоступен. VM засыпает после 5 минут простоя; персистентность — `/workspace/home` (30 дней) и S3FS-маунт в Cloudflare R2 (`/var/openrouter/session`).

Главные зацепки для дальнейшего копания: `createTunnel`/`tunnelService` (есть в DI, HTTP-эндпоинта нет), VSOCK-канал к хосту (dropbear, debug console, snapshot agent), и возможность форсировать прямой доступ к `/api/execute` в обход модели.

---

## 2. Архитектура

### 2.1. Физическая инфраструктура

| Параметр | Значение |
|---|---|
| Платформа | Cloudflare Containers |
| Гипервизор | `cloudflare-microvm` (Firecracker-подобный) |
| Ядро | `6.18.54-cloudflare-microvm-2026.9.16` |
| Хост VM | `cloudchamber` |
| Базовая ОС | Ubuntu 22.04.5 LTS (Jammy) |
| Container runtime | `crun` (OCI) и `csprint` (внутренний рантайм Cloudflare, не runc) |
| Миграция | VM переезжает между ДЦ в рамках сессии: `ams06 → lhr20 → ams19 → cdg17` (Амстердам / Лондон / Париж) |

### 2.2. Идентификаторы окружения (env внутри VM)

```
CLOUDFLARE_APPLICATION_ID    = a03a5724-f9ee-455a-8f21-dc9a2599d973
CLOUDFLARE_DEPLOYMENT_ID     = <UUID, меняется при каждом запуске>
CLOUDFLARE_PLACEMENT_ID      = <UUID, меняется>
CLOUDFLARE_DURABLE_OBJECT_ID = <64 hex>
CLOUDFLARE_NODE_ID           = <формат NNNmNNN>
CLOUDFLARE_LOCATION          = ams19 | cdg17 | fra19 | lhr14 | lhr20 | ams06
CLOUDFLARE_REGION            = WEUR | EEUR
CLOUDFLARE_COUNTRY_A2        = NL | FR | GB | DE
SANDBOX_VERSION              = 0.12.9
PYTHON_POOL_MIN_SIZE         = 3
JAVASCRIPT_POOL_MIN_SIZE     = 3
TYPESCRIPT_POOL_MIN_SIZE     = 3
```

### 2.3. Железо

| Параметр | Значение |
|---|---|
| CPU | AMD EPYC, 1 vCPU (виртуализация KVM, AMD-V) |
| RAM | 1.2 ГБ (1 242 872 kB), без swap |
| MemAvailable | ~875 МБ |
| Диск `/` | 3.7 ГБ (`/dev/vdc`, ext4), 2.5 ГБ свободно |
| `vda` | 9.6 МБ, ro (squashfs, ядро) |
| `vdb` | 128 МБ, ro (образ) |
| `vdd` | 150 МБ, rw (snapshots) |
| GPU | отсутствует — ни `lspci`, ни `/dev/dri`, ни `/dev/nvidia` |
| cgroup `memory.max` | не задан |
| cgroup `cpu.max` | не задан |
| cgroup `cpuset` | только CPU 0, NUMA node 0 |
| DMI | вырезан — `product_name`, `sys_vendor`, `bios_vendor` пустые |
| uptime на старте | 2 ч 8 мин (сама VM-хост живёт долго, по сути делится между сессиями) |

**Pre-loaded процессы** (ещё до первой команды пользователя):

```
PID 67:  /container-server/sandbox      (Bun-сервер, ~56 МБ)
PID 74:  ipython_executor.py            (~48 МБ)
PID 75:  node_executor.js               (~48 МБ)
PID 91:  node_executor.js               (~48 МБ)
PID 92:  node_executor.js               (~48 МБ)
PID 106: node_executor.js               (~48 МБ)
PID 107: node_executor.js               (~48 МБ)
```

≈340 МБ занято пулом из 1 Python- и 5 JS-экзекьюторов ещё до первой команды — отсюда ощутимая "выжимаемость" доступной RAM.

### 2.4. Загрузка ядра

**cmdline:**

```
reboot=k panic=1 pci=off nomodule
i8042.noaux i8042.nokbd i8042.nopnp quiet
ifname=cfeth0:00:11:22:33:44:66
systemd.hostname=localhost
root=/dev/vda ro
virtio_mmio.device=4K@0xd0000000:5
virtio_mmio.device=4K@0xd0001000:6
virtio_mmio.device=4K@0xd0002000:7
virtio_mmio.device=4K@0xd0003000:8
virtio_mmio.device=4K@0xd0004000:9
virtio_mmio.device=4K@0xd0005000:10
```

Расшифровка:
- `pci=off` — PCI отсутствует, только virtio-mmio (классический стиль Firecracker).
- `panic=1` — при panic ребут через 1 секунду.
- 6 virtio-устройств через MMIO: сеть, диски, vsock.
- `i8042.nokbd/nopnp/noaux` — отключены клавиатура/мышь/PS2.

**dmesg (boot log):**

```
[0.126] VFS: Mounted root (squashfs) readonly on device 253:0
[0.195] EXT4-fs (vdb): mounted filesystem fba99769-... ro
[0.195] EXT4-fs (vdd): mounted filesystem c7d1f65d-... r/w
[0.199] virtio_net virtio4 cfeth0: renamed from eth0
[5818] EXT4-fs (vdc): mounted filesystem 3bf9c56f-... r/w without journal
```

`/dev/vdc` (основной rw-диск, 3.7 ГБ) монтируется только на 5818-й секунде — то есть почти через 1.6 часа после старта ядра. VM стартует с read-only squashfs (быстрый boot, 0.2 сек до init), а полноценные rw-данные подключаются значительно позже — похоже на lazy-attach тома при переиспользовании/миграции VM между сессиями.

---

## 3. Права и изоляция

| Параметр | Значение |
|---|---|
| uid/gid | `0/0` (root) |
| Seccomp | отключён (`Seccomp: 0`, `Seccomp_filters: 0`) |
| CapEff | `000001ffffffffff` — полный набор |
| CapPrm | `000001ffffffffff` |
| CapBnd | `000001ffffffffff` |
| `CAP_SYS_ADMIN` | есть |
| `CAP_SYS_MODULE` | есть |
| `CAP_BPF` | есть |
| `CAP_NET_ADMIN` | есть |
| `CAP_NET_RAW` | есть |

Иначе говоря: **внутри VM мы — почти боги** (root + полный CapEff + отключённый seccomp), но сама VM изолирована от хоста через гипервизор и собственные namespace'ы.

### 3.1. Namespaces контейнера

Из `bundle/config.json` (`linux.namespaces`):

| Namespace | Статус |
|---|---|
| `pid` | отдельный, наш (не хост VM) |
| `net` | отдельный, но общий с Bun-сервером (поэтому виден `10.0.0.1:3000`) |
| `ipc` | отдельный |
| `user` | отдельный |
| `uts` | наш |
| `mount` | наш |
| `cgroup` | наш |

### 3.2. Лимиты

```json
"rlimits": [
  {"type": "RLIMIT_NOFILE", "hard": 1024, "soft": 1024},
  {"type": "RLIMIT_NOFILE", "hard": 1048576, "soft": 1048576}
]
```

---

## 4. Файловая система

### 4.1. Основные пути

| Путь | Назначение | Размер / примечание |
|---|---|---|
| `/` | Rootfs overlay | 3.7 ГБ (`/dev/vdc`) |
| `/workspace/home` | Persistent storage | живёт 30 дней |
| `/var/openrouter/session` | S3FS → Cloudflare R2 | номинально 16 ЭБ |
| `/container` | Bundle контейнера (read) | — |
| `/container/rootfs` | Настоящий rootfs | — |
| `/container/bundle` | OCI-бандл | — |
| `/container-server` | Сервер песочницы (Bun) | 100 МБ бинарь + 266 КБ JS |
| `/tmp/session-sandbox-shell-*` | Логи текущей сессии | эфемерный |
| `/run/crun/cloudchamber` | Состояние `crun` | — |
| `/run/csprint/` | Runtime-директория `csprint` | — |
| `/etc/cloudflare/environ.json` | Маркеры Cloudflare (read-only) | 251 Б |
| `/etc/cloudchamber-template-network/` | Шаблон сети | — |
| `/etc/cloudflare/certs/cloudflare-containers-ca.crt` | CA Cloudflare | — |
| `/var/openrouter/ready` | `user_id` + placement UUID | 69 Б |

Внутри VM доступна вся ФС `/` (root), кроме read-only `/sys`, частично `/proc`.

### 4.2. Монтирования (overlay)

```
/dev/vdc          /                  ext4      rw
overlay           /etc/hostname      ro   lowerdir=/container/bundle/etc:/etc  upperdir=/container/etc
overlay           /etc/hosts         ro   lowerdir=/container/bundle/etc:/etc  upperdir=/container/etc
overlay           /etc/resolv.conf   rw   lowerdir=/container/bundle/etc:/etc  upperdir=/container/etc
s3fs              /var/openrouter/session  fuse.s3fs rw
```

### 4.3. S3FS / Cloudflare R2

Команда монтирования:

```
s3fs R2_FILES_SESSION /var/openrouter/session \
  -o passwd_file=/tmp/.passwd-s3fs-<uuid>,\
     stat_cache_expire=60,\
     enable_noobj_cache,\
     multipart_size=5,\
     nomixupload,\
     use_path_request_style,\
     url=http://r2.internal,\
     ahbe_conf=/tmp/.s3fs-ahbe-<uuid>.conf
```

Детали параметров:
- `url=http://r2.internal` — внутренний Cloudflare DNS, снаружи не резолвится.
- `stat_cache_expire=60` — кэш метаданных на 60 секунд.
- `enable_noobj_cache` — кэшируется информация «объект не существует» (для пустых листингов).
- `multipart_size=5` — чанки по 5 МБ.
- `nomixupload` — запрет смешивания режимов аплоада.
- `use_path_request_style` — path-style адресация, не virtual-hosted.
- `ahbe_conf` — additional header/body exclusion (содержимое: `Expect:`).

Креды: `/tmp/.passwd-s3fs-<uuid>` (20 байт) — формат `R2_FILES_SESSION:x:x`. Это заглушка; реальная аутентификация идёт через внутреннюю инфраструктуру Cloudflare.

**Проверено на практике:**

```bash
echo "probe $(date)" > /var/openrouter/session/probe.txt   # OK
cat /var/openrouter/session/probe.txt                       # probe Fri Oct 16 15:12:14 UTC 2026
ls -la /var/openrouter/session/                              # -rw-r----- 1 root root 35 ... probe.txt
```

`df -h` показывает номинальные 16 ЭБ (размер бакета), реальные лимиты — на стороне OpenRouter. **Cross-session persistence не подтверждена** — каждый новый вызов `or`/`openrouter:shell` без `container_reference` — это новая VM.

---

## 5. Сеть

### 5.1. Сетевая конфигурация

Файл `/etc/cloudchamber-template-network/10-cfeth0.network`:

```ini
[Match]
Name=cfeth0
MACAddress=00:11:22:33:44:66

[Link]
MTUBytes=1420

[Network]
DHCP=No
LinkLocalAddressing=no

[Address]
Address=10.0.0.1/24

[Route]
Gateway=10.0.0.254        # хост-шлюз
Destination=0.0.0.0/0

[Address]
Address=fd00::11/8

[Route]
Gateway=fd00::22
PreferredSource=fd00::11
Destination=::/0
```

DNS: `2606:4700:4700::1111` (Cloudflare), `2620:fe::fe` (Quad9).

Детали:
- `Gateway=10.0.0.254` — это шлюз хоста VM, а не OpenRouter API.
- MTU 1420 (не стандартные 1500) — типично для туннелируемых сетей.
- DHCP отключён, адреса статические.
- IPv6 `fd00::11/8` — внутренний диапазон Cloudflare.

### 5.2. Живые TCP-соединения

Зафиксировано прямое соединение:

```
020200C0:8854 → 0A684FA0:01BB
```
→ Локальный `192.168.2.2:34892` (пример) → Удалённый `160.79.104.10:443` (диапазон Cloudflare, порт 443/HTTPS).

IP `160.79.104.10` — эндпоинт, к которому реально обращается sandbox-инфраструктура. В DNS-записях он не фигурирует явно, но соединение устанавливается напрямую (вероятно, служебный канал самого Bun-сервера/песочницы, а не доступный нам egress).

### 5.3. Ограничения (egress)

- **Исходящий HTTPS не работает** — ни по IPv4, ни по IPv6. Таймаут на всё внешнее.
- DNS резолвится, но соединение не проходит (встречается внутренний DNS `fd00::119:1`).
- Egress-прокси работает по **allowlist доменов** (не по IP), список по умолчанию **пустой**.
- `cloudflared` не может достучаться до `api.trycloudflare.com`.
- `mcp-proxy.anthropic.com` не резолвится из VM.
- SSH/nc/socat — отсутствуют в образе (см. раздел 13).

---

## 6. HTTP API песочницы

Endpoint: **`http://10.0.0.1:3000`** — Bun-сервер, **работает без авторизации по умолчанию**, проверено прямым `curl`, ответ ~0.1 сек.

### 6.1. Execution

| Метод | Путь | Body | Ответ |
|---|---|---|---|
| POST | `/api/execute` | `{"command":"..."}` | `{"success":true,"exitCode":0,"stdout":"...","stderr":"","duration":0}` |
| POST | `/api/execute/stream` | `{"command":"..."}` | SSE-поток, построчный вывод долгих команд |
| POST | `/api/execute/code` | `{"contextId":"...","code":"..."}` | `{"success":true,...}` (требует существующий `contextId`) |

### 6.2. Files

| Метод | Путь | Body |
|---|---|---|
| POST | `/api/read` | `{"path":"..."}` → `{"content":"<base64>"}` |
| POST | `/api/write` | `{"path":"...","content":"..."}` |
| POST | `/api/list-files` | `{"path":"..."}` → `{"files":[{name,type,size,mode,modified,...}]}` |
| POST | `/api/mkdir` | `{"path":"..."}` |
| POST | `/api/delete` | `{"path":"..."}` |
| POST | `/api/rename` | `{"from":"...","to":"..."}` |
| POST | `/api/move` | `{"from":"...","to":"..."}` |
| POST | `/api/exists` | `{"path":"..."}` |

### 6.3. Processes

| Метод | Путь |
|---|---|
| POST | `/api/process/start` |
| GET | `/api/process/list` |
| DELETE | `/api/process/kill-all` |
| GET | `/api/process/{id}` |
| DELETE | `/api/process/{id}` |
| GET | `/api/process/{id}/logs` |
| GET | `/api/process/{id}/stream` |

Фоновые процессы умирают вместе с VM.

### 6.4. Sessions

| Метод | Путь | Body |
|---|---|---|
| POST | `/api/session/create` | `{"sessionId":"..."}` → возвращает `id`, `sessionDir`, `ready:true` |
| GET | `/api/session/list` | — |
| POST | `/api/session/delete` | `{"sessionId":"..."}` |

Состояние между вызовами **не сохраняется** — сама VM одноразовая.

### 6.5. Interpreter (persistent Python/JS)

| Метод | Путь | Body |
|---|---|---|
| GET | `/api/interpreter/health` | — |
| POST | `/api/contexts` | `{"language":"python"}` → `{"contextId":"...","language":"python","cwd":"/workspace"}` |
| GET | `/api/contexts` | → список активных контекстов |
| DELETE | `/api/contexts/{id}` | — |

Переменные **сохраняются между вызовами** `/api/execute/code` с одним и тем же `contextId` — это встроенный персистентный IPython (а также JS/TS, см. раздел 16).

### 6.6. Backup

| Метод | Путь | Body |
|---|---|---|
| POST | `/api/backup/create` | `{"dir":"...","archivePath":"/var/backups/..."}` |
| POST | `/api/backup/restore` | `{"dir":"...","archivePath":"...","backupId":"..."}` |
| POST | `/api/backup/upload-parts` | multipart, формат не выяснен |

Ограничение: `archivePath` обязан лежать в designated backup directory (обычно `/var/backups/`), иначе — `Invalid archivePath: must use designated backup directory`.

### 6.7. Git

| Метод | Путь |
|---|---|
| POST | `/api/git/checkout` |
| POST | `/api/git/clone` |
| POST | `/api/git/operation` |

### 6.8. Прочее

| Метод | Путь | Ответ |
|---|---|---|
| GET | `/api/ping` | `{"success":true,"status":"healthy"}` |
| GET | `/api/version` | — |
| GET | `/api/watch` | — |
| POST | `/api/watch/check` | — |
| POST | `/api/port-watch` | — |
| POST | `/api/shutdown` | — |

### 6.9. Авторизация и CORS

Авторизация (если требуется) читается в таком порядке:

1. `Authorization: Bearer <session_id>`
2. `X-Session-Id: <session_id>`
3. Query `?session=...` или `?sessionId=...`

**Дефолтный `/api/*` — без авторизации.**

CORS-заголовки:

```
Access-Control-Allow-Headers: Content-Type, Authorization, X-Session-Id, X-Sandbox-Id, X-Trace-Id
Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS
Access-Control-Allow-Origin:  *
```

---

## 7. WebSocket RPC

### 7.1. Пути и протокол

| Путь | Статус |
|---|---|
| `/ws` | 101 Switching Protocols ✅ |
| `/rpc` | 101 Switching Protocols ✅ |
| `/api/ws` | — |
| `/` (корень) | отдаёт 200 OK, **не** апгрейдится до WS |

Формат запроса клиента:

```json
{
  "type": "request",
  "id": "<string>",
  "method": "GET|POST|PUT|DELETE",
  "path": "/api/...",
  "body": {...}
}
```

Форматы ответа сервера:

```json
{"type": "response", "id": "<string>", "status": 200, "body": {...}, "done": true}
{"type": "stream",   "id": "<string>", "event": "...", "data": [...]}
{"type": "error",    "id": "<string>", "code": "...", "message": "...", "status": 500}
```

Отмена запроса:

```json
{"type": "cancel", "id": "<request id>"}
```

### 7.2. Каталог RPC-методов (из `index.js`)

```
command.execute, command.stream

process.start, process.list, process.kill, process.get, process.logs

git.clone, git.checkout, git.operation

backup.create, backup.restore, backup.unmount

code.execute, code.context.create, code.context.delete

session.create, session.destroy

file.read, file.write, file.delete, file.mkdir
```

---

## 8. Сервисы Bun-сервера (DI)

Из `dist/index.js`, инициализируются через `c8.initialize()` — более 20 сервисов:

| Сервис | Назначение |
|---|---|
| `processService` | Управление процессами |
| `fileService` | Файловые операции |
| `portService` | Проверка портов |
| `gitService` | Git-операции |
| `interpreterService` | Python/JS-интерпретаторы |
| `backupService` | Бэкапы через `/var/backups` |
| `watchService` | Файловые watchers |
| `tunnelService` | Туннели (**HTTP-эндпоинт не найден**, см. раздел 16) |
| `logger` | Логирование (structured / json-line / pretty) |
| `security` | Санитизация URL, маскировка credentials |
| `sessionManager` | Управление сессиями |
| `executionService` | Выполнение команд |
| `corsMiddleware` | CORS |
| `loggingMiddleware` | Логирование запросов |
| `ptyWsHandler` | PTY через WebSocket (эндпоинт не найден) |
| `backupHandler`, `executeHandler`, `fileHandler`, `processHandler`, `portHandler`, `gitHandler`, `interpreterHandler`, `sessionHandler`, `miscHandler`, `watchHandler` | HTTP-обработчики соответствующих сервисов |

---

## 9. Переменные окружения

### 9.1. Логирование

| Переменная | Значения | По умолчанию |
|---|---|---|
| `SANDBOX_LOG_LEVEL` | `debug\|info\|warn\|error` | `info` |
| `SANDBOX_LOG_FORMAT` | `pretty\|json-line\|structured` | `structured` |

### 9.2. Пул исполнителей

| Переменная | Значение |
|---|---|
| `PYTHON_POOL_MIN_SIZE` | 3 |
| `JAVASCRIPT_POOL_MIN_SIZE` | 3 |
| `TYPESCRIPT_POOL_MIN_SIZE` | 3 |

---

## 10. Init-процесс (Rust)

Файл: `/proc/1/root/sbin/init` — 7.3 МБ ELF, **not stripped**, написан на Rust.
Запуск: `/sbin/init nomodule`.

### 10.1. Флаги конфигурации (из `strings init`)

| Флаг | Эффект |
|---|---|
| `cloudchamber.debug=1` | включает **debug console** на VSOCK |
| `cloudchamber.init_debug_logs=1` | init debug-логирование |
| `cloudchamber.verbose=1` | verbose logs |
| `cloudchamber.pid` | путь PID-файла |
| `cloudchamber.container_rpc_window_bytes` | размер окна RPC |
| `cloudchamber.shutdown_startup_grace_period` | тайминг shutdown |
| `cloudchamber.snapshot_export_transactions_max_size_bytes` | лимит снапшотов |
| `cloudchamber.max_termination_duration` | тайминг завершения |
| `cloudchamber.cspno`, `cloudchamber.debid`, `cloudchamber.temmld_v`, `cloudchamber.test`, `cloudchamber.invalid`, `cloudchamber.Error` | встречены в бинаре, назначение не выяснено |

Конфиг: `/etc/cloudchamber.ini` — **не существует** по умолчанию (`init_debug_logs=1` упомянут именно там).

### 10.2. VSOCK-сервисы

| Сервис | Назначение |
|---|---|
| `logrelayd` | Передача логов на хост |
| `syslog` | Системный лог |
| Debug console | Интерактивный shell (требует `cloudchamber.debug=1`) |
| `snapshot_agent` | Snapshot/freeze/rollback состояния VM (через btrfs) |
| `container_rpc_server` | RPC-сервер, принимающий команды от хоста |

Транспорт: крейты `tokio-vsock-0.5.4`, `vsock-0.5.4` (Rust).

Защита: `SECURITY: rejected VSOCK connection from CID X (only host CID Y)` — dropbear и прочие VSOCK-сервисы принимают соединения **только от хост-CID**.

### 10.3. Snapshot-модули

```
rust/init/src/snapshot_agent/mod.rs
rust/init/src/snapshot_agent/export.rs
rust/init/src/snapshot_agent/export_create.rs
rust/init/src/snapshot_agent/export_budget.rs
rust/init/src/snapshot_agent/export_journal.rs
rust/init/src/snapshot_agent/freeze.rs
rust/init/src/snapshot_agent/validation.rs
```

Использует `btrfs` (`/usr/bin/btrfs`, `/usr/bin/btrfssnaps`).

Строки сообщений, найденные в init:

```
Snapshot: freeze failed
Snapshot: failed to roll back
Snapshot: failed to promote export transaction
Snapshot: failed to reclaim committed export transactions
snapshot export transaction budget scan in
snapshot export already in progress for generation
```

Директории `/proc/1/root/run/csprint/` и `/proc/1/root/var/lib/csprint/` **не существуют** в работающей VM — создаются только при фактическом использовании.

### 10.4. Container runtime `csprint`

Собственный рантайм Cloudflare (не `runc`):

```
rust/init/src/csprint/cli.rs
rust/init/src/csprint/container.rs
rust/init/src/csprint/exec.rs
rust/init/src/csprint/lib.rs
rust/init/src/csprint/mounts.rs
rust/init/src/csprint/spec.rs
```

Стадии запуска контейнера (видны как имена трейсов/спанов):

```
container.start.spawn_runtime.claim_csprint
container.start.spawn_runtime.csprint.deliver
container.start.spawn_runtime.csprint.cgroup
container.start.spawn_runtime.csprint.plan
container.start.spawn_runtime.csprint.fork
container.start.spawn_runtime.csprint.setup
container.start.spawn_runtime.csprint.execve
```

Связанные файлы: `/run/csprint/`, `/run/csprint/empty`, `/run/csprint/null`.

---

## 11. Dropbear SSH / ccsh

### 11.1. Файлы

```
/usr/sbin/dropbear       (507 КБ, ELF, NOT STRIPPED)
/usr/sbin/dropbearkey    (217 КБ)
/usr/local/bin/ccsh      (378 КБ, SUID root, STRIPPED)
/usr/local/bin/configure-sshd
```

`ccsh` подтверждён как SUID root:

```
-rwsr-xr-x 1 root root 378312 Jan 1 2000 /proc/1/root/usr/local/bin/ccsh
```

Бит `s` в правах = SUID: бинарь выполняется от root даже при вызове обычным пользователем. Это обёртка для SSH-сессии (CloudChamber Shell).

### 11.2. Аргументы запуска dropbear

```
/usr/sbin/dropbear -p <PORT> -s -I -F -E -r <host_key>
```

- `-p` — порт
- `-s` — только ключи (без пароля)
- `-I` — не читать `/etc/motd`
- `-F` — foreground
- `-E` — лог в stderr
- `-r` — host key

### 11.3. Ключи и конфигурация

```
/etc/dropbear/dropbear_ed25519_host_key
/etc/dropbear/dropbear_ecdsa_host_key
/etc/ssh/authorized_keys/cloudchamber             (по умолчанию пусто)
/etc/ssh/authorized_keys/cloudchamber-ted25519
/etc/ssh/trusted_user_ca_keys
/etc/systemd/system/ssh.service.d/override-execstartpre.conf
```

**Принудительная команда:** `command="/usr/local/bin/ccsh"`
**Транспорт:** VSOCK (не TCP)
**Условие запуска:** claim-time + наличие authorized keys. При пустых ключах: `No SSH authorized keys found; skipping dropbear.`

Слушает **только от host CID** (см. `SECURITY: rejected VSOCK connection` в разделе 10.2).

Штатный systemd-юнит SSH отключён:

```
/etc/systemd/system/ssh.service -> /dev/null
```

### 11.4. Почему `ccsh` не работает напрямую

```
ccsh: crun exec failed: No such file or directory (os error 2)
```

`ccsh` — SUID-обёртка, которая пытается вызвать `crun exec` внутри **нашего** контейнера, но `crun` не находится в `PATH` текущего окружения.

---

## 12. Внешний OpenRouter API

### 12.1. Responses API и серверный инструмент `openrouter:shell`

Endpoint: `https://openrouter.ai/api/v1/responses`

```json
{
  "type": "openrouter:shell",
  "parameters": {
    "engine": "openrouter",
    "environment": {
      "type": "container_reference",
      "container_id": "termux-box"
    },
    "network_policy": {
      "type": "allowlist",
      "allowed_domains": ["*"]
    },
    "file_ids": ["file-xxx"]
  }
}
```

### 12.2. Два транспорта

| Tool | API | Engine |
|---|---|---|
| `openrouter:shell` | Responses + Messages | `auto` / `openrouter` |
| `openrouter:bash` | только Messages | обязательно `openrouter` для серверного инструмента |

### 12.3. Типы `environment`

| Тип | Поведение |
|---|---|
| `container_auto` | Новый контейнер на каждый запрос. С `session_id` → `sess_<id>` |
| `container_reference` | Фиксированный ID (1–40 символов: `[a-zA-Z0-9_-]`) — позволяет переиспользовать VM между вызовами |

### 12.4. Files API

```
POST   /api/v1/files                               → загрузить файл
GET    /api/v1/containers/{id}/files               → список файлов
GET    /api/v1/containers/{id}/files/{fid}/content  → скачать
```

### 12.5. Формат ответа и стоимость

```json
{
  "output": [
    {"type": "reasoning", "content": [...]},
    {"type": "openrouter:shell",
     "action": {"commands": ["..."]},
     "output": [{"stdout": "...", "stderr": "...", "outcome": {"type": "exit", "exit_code": 0}}],
     "container_id": "termux-box",
     "call_id": "call-..."},
    {"type": "message", "content": [{"type": "output_text", "text": "..."}]}
  ],
  "usage": {
    "cost": 0.003,
    "cost_details": {"server_tool_cost": 0.003}
  }
}
```

Стоимость: `server_tool_cost = $0.003` за вызов VM, **независимо от выбранной модели**.

Полезно: читая `output[].type == "openrouter:shell"`, можно получать `stdout`/`stderr` **в сыром виде**, минуя пересказ модели — это быстрее и дешевле, чем просить модель вручную процитировать вывод команды.

---

## 13. Что установлено в образе

**Есть:**

```
python3 (3.11, /usr/local/python/bin/)
node    (v22, ≈124 МБ)
bun     (/usr/local/bin/bun, ≈100 МБ)
npm, npx, tsc
curl, wget, git, jq
pip3 (есть /usr/local/python/bin/pip3, но без venv)
cloudflared 2026.3.0 (≈39 МБ, не работает — DNS/egress блок)
crun (статика, ≈2 МБ, stripped)
dropbear, dropbearkey
btrfs, btrfssnaps (btrfs-progs)
mksquashfs, fuse-overlayfs, fusermount3
s3fs (FUSE S3)
fonts-* (для Chromium)
```

**Нет:**

```
pip (голый симлинк, без venv — по факту не функционален)
gcc, g++, make
docker, kubectl
rg (ripgrep), fd
go, rustc
socat, nc, ncat
strings (из binutils)
ssh (клиент)
```

---

## 14. Сводка: что работает / что нет

### 14.1. Работает ✅

| Возможность | Через что | Ограничение |
|---|---|---|
| Прямой shell в microVM | `POST /api/execute` | ~100 мс на выполнение (но через модель-ретранслятор — 10–120 сек) |
| Чтение/запись файлов | `/api/read`, `/api/write` | только внутри VM |
| Фоновые процессы | `/api/process/start` | умирают вместе с VM |
| Persistent Python/JS | `/api/contexts` + `/api/execute/code` | переменные живут, пока жив `contextId` |
| WebSocket RPC | `/ws`, `/rpc` | 101 Switching Protocols подтверждён |
| VM как одноразовый Linux | в целом | VM гибнет через 5 мин простоя |
| Root + полные caps | — | ограничено рамками VM/namespace |
| S3FS-хранилище | `/var/openrouter/session` | запись/чтение внутри сессии подтверждены |
| `/workspace/home` | персистентность 30 дней | — |
| Backup/restore | `/api/backup/*` | только designated directory |

### 14.2. Не работает ❌

| Что | Статус | Причина |
|---|---|---|
| Исходящий HTTPS (IPv4/IPv6) | ❌ | Таймаут на всё внешнее, egress-прокси + allowlist (по умолчанию пуст) |
| DNS → соединение | ❌ | Резолвится, но коннект не проходит |
| `cloudflared tunnel` | ❌ | `api.trycloudflare.com` не достижим |
| SSH (клиент/сервер) | ❌ | Отключён без `authorized_keys`; `nc`/`socat` отсутствуют в образе |
| `ccsh` | ❌ | `crun exec failed: No such file or directory` (нет `crun` в PATH) |
| `AF_VSOCK` в Python | ❌ | `module 'socket' has no attribute 'AF_VSOCK'` |
| WS на `/` (корень) | ❌ | Отдаёт 200 OK, не апгрейдится |
| `init --help` | ❌ | `GLIBC_2.39 not found` (у нас 2.35) |
| `/api/tunnel/create` | ❌ | 404 — не HTTP-эндпоинт |
| R2 из внешней сети (Termux) | ❌ | `r2.internal` не резолвится снаружи |
| `pip`, `gcc` | ❌ | Отсутствуют в образе |
| Cross-session persistence | ⚠️ | Не подтверждена — каждый вызов `or` обычно новая VM |

---

## 15. Ошибки и логи (для отладки)

**Egress-прокси:**

```
[network] ('Connection aborted.', RemoteDisconnected('Remote end closed connection without response'))
[network] HTTPSConnectionPool(host='openrouter.ai', port=443): Max retries exceeded
[network] HTTPSConnectionPool(host='openrouter.ai', port=443): SSLError(SSLEOFError(8, '[SSL: UNEXPECTED_EOF_WHILE_READING]'))
```

**Sandbox API:**

```
{"code":"INVALID_BACKUP_CONFIG","message":"Missing or invalid field: dir"}
{"code":"INVALID_BACKUP_CONFIG","message":"Missing or invalid field: archivePath"}
{"code":"INVALID_BACKUP_CONFIG","message":"Invalid archivePath: must use designated backup directory"}
{"error":"Context undefined not found","code":"CONTEXT_NOT_FOUND","details":{}}
{"code":"UNKNOWN_ERROR","message":"Invalid endpoint","context":{},"httpStatus":500}
```

**VSOCK:**

```
vsock err: module 'socket' has no attribute 'AF_VSOCK'
Python: OSError: [Errno 97] Address family not supported by protocol
```

**SSH/init:**

```
ccsh: crun exec failed: No such file or directory (os error 2)
GLIBC_2.39 not found (required by /proc/1/root/sbin/init)
```

Дополнительно известно, что `/api/commands` отдаёт `500` и, по всей видимости, требует другой формат тела запроса (не выяснен).

---

## 16. Непроверенное и потенциальные направления

| Что | Статус | Как можно проверить |
|---|---|---|
| `createTunnel` RPC | ⚠️ метод есть в DI (`tunnelService`), HTTP-путь не найден | Через WebSocket `/ws`/`/rpc` с разными вариантами `path`/`method` |
| `ptyWsHandler` | ⚠️ сервис есть, путь неизвестен | Перебор WS-путей, может давать полноценный PTY |
| Snapshot/freeze API | ⚠️ модули в init есть | Через флаги `cloudchamber.*` + `snapshot_agent`, нужен контроль над cmdline VM |
| `/api/backup/upload-parts` | ⚠️ | Нужно выяснить формат multipart |
| Persistent Python между сессиями | ⚠️ | `container_reference` + сохранённый `contextId` между вызовами `or` |
| `/api/commands` | ⚠️ 500 | Требует другой формат body, не выяснен |
| VSOCK к хосту (`10.0.0.254` / CID 2) | ⚠️ | Через `ctypes`/raw ioctl, т.к. `AF_VSOCK` недоступен штатно в Python |
| `/sbin/init` (7 МБ ELF) | ⚠️ | Не разобран полностью через `strings` (нет в образе) — потенциально содержит IP хостовой сети, endpoint'ы, ключи |
| `vhost-vsock` устройство | ⚠️ есть, инструментов нет | Можно написать raw-клиент на C (`gcc` отсутствует) или через Python `ioctl` |
| Доп. порты Bun-сервера | ⚠️ | Сервер слушает `10.0.0.1:3000`; не исключены другие порты (8080, 9090) или недокументированные пути |
| `/api/execute/code` — языки | Python + JS подтверждены | Проверить, поддерживается ли TypeScript как отдельный `language` |
| `container_id` предсказуемость | ⚠️ | `container_reference` создаёт предсказуемый ID — можно исследовать переиспользование состояния |

### Варианты направлений (из исходной "инвентаризации")

Ниже — зафиксированные варианты дальнейшего исследования, как они были сформулированы изначально:

- **A. WebSocket RPC** — попытка получить `createTunnel` изнутри VM. Если сработает — прямой URL на `/api/execute`, всё быстрое.
- **B. `/sbin/init`** — `strings` + анализ бинаря: вероятно, там адреса хостовых сервисов или ключи.
- **C. Оптимизация текущего пути** — написать `or_agent.py`, который использует модель только как ретранслятор (минимальный промпт, один tool call), укладываясь в 2–3 секунды.
- **D. Reverse-туннель через собственный VPS** — если из VM есть хоть какой-то исходящий канал (проверить raw-сокеты на нестандартные порты 53/443/8443).

---

## 17. Практическая шпаргалка

### 17.1. Проверить мост

```bash
curl http://10.0.0.1:3000/api/ping
# → {"success":true,"status":"healthy"}
```

### 17.2. Выполнить команду

```bash
curl -sS -X POST http://10.0.0.1:3000/api/execute \
  -H 'Content-Type: application/json' \
  -d '{"command":"uname -a && id"}'
```

### 17.3. Persistent Python

```bash
# Создать context:
CTX=$(curl -sS -X POST http://10.0.0.1:3000/api/contexts \
  -H 'Content-Type: application/json' \
  -d '{"language":"python"}' | jq -r '.contextId')

# Выполнить код:
curl -sS -X POST http://10.0.0.1:3000/api/execute/code \
  -H 'Content-Type: application/json' \
  -d "{\"contextId\":\"$CTX\",\"code\":\"import os; print(os.listdir('/'))\"}"

# Переменные сохраняются между вызовами с тем же CTX
```

### 17.4. WebSocket RPC

```bash
bun -e '
const ws = new WebSocket("ws://10.0.0.1:3000/ws");
ws.onopen = () => {
  ws.send(JSON.stringify({
    type: "request", id: "1", method: "GET",
    path: "/api/session/list", body: null
  }));
};
ws.onmessage = e => console.log(e.data);
'
```

### 17.5. Работа с файлами через API

```bash
curl -sS -X POST http://10.0.0.1:3000/api/write \
  -H 'Content-Type: application/json' \
  -d '{"path":"/workspace/home/test.txt","content":"hello"}'

curl -sS -X POST http://10.0.0.1:3000/api/read \
  -H 'Content-Type: application/json' \
  -d '{"path":"/workspace/home/test.txt"}' | jq -r .content | base64 -d
```

### 17.6. Через внешний OpenRouter API

```bash
curl -sS https://openrouter.ai/api/v1/responses \
  -H "Authorization: Bearer $OPENROUTER_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "nvidia/nemotron-3.5-lightning:free",
    "input": "Run shell: uname -a",
    "tools": [{
      "type": "openrouter:shell",
      "parameters": {
        "engine": "openrouter",
        "environment": {"type": "container_reference", "container_id": "termux-box"}
      }
    }]
  }' | jq '.output[] | select(.type=="openrouter:shell") | .output[0].stdout'
```

---

## 18. Карта сервисов

```
┌─────────────────────────────────────────────────────┐
│                 Cloudflare Containers                │
│                                                       │
│  ┌──────────── VM (10.0.0.1/24) ──────────────────┐  │
│  │                                                 │  │
│  │  ┌── /sbin/init (Rust, 7.3 МБ) ──┐              │  │
│  │  │  • dropbear (VSOCK, port X)   │              │  │
│  │  │  • logrelayd (VSOCK)          │              │  │
│  │  │  • syslog (VSOCK)             │              │  │
│  │  │  • snapshot_agent (btrfs)     │              │  │
│  │  │  • container_rpc_server       │              │  │
│  │  │  • csprint (container runtime)│              │  │
│  │  └────────────────────────────────┘             │  │
│  │                                                 │  │
│  │  ┌── /container-server/sandbox ──┐              │  │
│  │  │  Bun-сервер на 10.0.0.1:3000  │              │  │
│  │  │  • HTTP API (без auth)        │              │  │
│  │  │  • WebSocket /ws, /rpc        │              │  │
│  │  │  • Python/JS pool (5+1)       │              │  │
│  │  └────────────────────────────────┘             │  │
│  │                                                 │  │
│  │  s3fs → r2.internal (Cloudflare R2, 16 ЭБ)      │  │
│  │  /workspace/home (30 дней)                      │  │
│  │  /var/openrouter/session (S3FS)                 │  │
│  └──────────────────────────────────────────────────┘ │
│                                                       │
│  Host: 10.0.0.254 (gateway)                          │
│  VSOCK: cid=?, ports=22, logrelayd, debug console    │
│                                                       │
└───────────────────────────────────────────────────────┘
```

**Внешние каналы (видимые модели, а не VM):**

- `openrouter.ai/api/v1/responses` — основной API (модель + tool shell)
- `openrouter.ai/api/v1/containers/{id}/files` — список файлов
- `openrouter.ai/api/v1/files` — upload
- `160.79.104.10:443` — прямые TCP-соединения, видимые изнутри VM (внутренний Cloudflare-эндпоинт)

---

## 19. Открытые вопросы / куда копать дальше

1. **`createTunnel`** — метод фигурирует в DI (`tunnelService`), но HTTP endpoint не найден. Если удастся вызвать его через `/ws` или `/rpc`, вероятно можно получить публичный URL на `/api/execute`, что уберёт задержку модели-ретранслятора (10–120 сек → ~100 мс).
2. **`/sbin/init`** — 7.3 МБ ELF-бинарь не до конца проанализирован (`strings` недоступен в образе; можно скопировать бинарь наружу через `/api/read` и проанализировать локально). Потенциально содержит адреса хостовых сервисов, ключи, скрытые флаги.
3. **VSOCK к хосту** — заблокирован на уровне "only host CID", но стоит проверить, можно ли инициировать соединение с другой стороны через `ctypes`/raw `ioctl` в Python, либо собрать минимальный raw-клиент (ограничение: `gcc` отсутствует, значит решение должно быть на Python или предкомпилированным).
4. **Reverse-туннель через собственный VPS** — проверить непривычные исходящие порты (53, 443, 8443) на предмет пропуска egress-прокси.
5. **Оптимизация пути через модель** — минимальный "ретрансляционный" агент (`or_agent.py`), чтобы каждый вызов `openrouter:shell` сводился к одному tool call с минимальным промптом — цель 2–3 секунды на команду вместо текущих 10–120.
6. **`/api/commands`** — отдельный от `/api/execute` эндпоинт, возвращает 500 с текущим форматом тела; нужно подобрать корректную схему запроса.
7. **TypeScript как язык `/api/execute/code`** — подтверждены Python и JS; `TYPESCRIPT_POOL_MIN_SIZE=3` намекает, что TS-контексты тоже поддерживаются.

---

*Документ составлен на основе прямого исследования работающего инстанса песочницы (`SANDBOX_VERSION=0.12.9`, 2026-10-16 — 2026-10-18). Данные могут устареть при обновлении версии песочницы.*
