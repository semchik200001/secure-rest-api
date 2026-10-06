# Secure REST API

[![CI](https://github.com/semchik200001/secure-rest-api/actions/workflows/ci.yml/badge.svg)](https://github.com/semchik200001/secure-rest-api/actions/workflows/ci.yml)

Учебный проект по дисциплине «Системы компьютерной обработки изображений», работа 1.

Небольшое REST API на Python и Flask: регистрация и вход пользователей, выдача JWT-токена, просмотр и создание постов. В проекте реализована защита от SQL-инъекций, XSS и Broken Authentication. При каждом push и pull request GitHub Actions автоматически запускает тесты, статический анализ кода (SAST) и проверку зависимостей (SCA).

## Стек

- Python 3.13, Flask 3.1
- SQLite (модуль `sqlite3` из стандартной библиотеки)
- PyJWT для JWT-токенов, bcrypt для хэширования паролей
- pytest для тестов
- Bandit (SAST), pip-audit и OWASP Dependency-Check (SCA)
- GitHub Actions (CI/CD)

## Структура проекта

```
secure-rest-api/
|-- app/
|   |-- __init__.py      # создание приложения, заголовки безопасности, обработчики ошибок
|   |-- db.py            # подключение к SQLite и схема БД
|   |-- auth.py          # регистрация, логин, JWT, middleware проверки токена
|   `-- api.py           # защищённые эндпоинты /api/*
|-- tests/
|   `-- test_api.py      # тесты API и мер защиты
|-- .github/
|   |-- workflows/ci.yml # pipeline GitHub Actions
|   `-- scripts/         # загрузка фидов NVD и отчёт Dependency-Check для summary
|-- docs/screenshots/    # скриншоты отчётов
|-- dependency-check-suppressions.xml  # подавление ложных срабатываний Dependency-Check
|-- run.py               # точка входа
|-- requirements.txt     # зависимости приложения
`-- requirements-dev.txt # зависимости для разработки и проверок
```

## Запуск

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt

export JWT_SECRET="$(python3 -c 'import secrets; print(secrets.token_urlsafe(64))')"
python3 run.py
```

Сервер запускается на `http://127.0.0.1:8000`. Порт можно поменять переменной `PORT`, путь к базе переменной `DATABASE_PATH`, время жизни токена (в минутах) переменной `JWT_TTL_MINUTES`. Пример переменных лежит в `.env.example`.

Тесты:

```bash
pytest -v
```

## API

Все запросы и ответы в формате JSON.

| Метод | Путь | Доступ | Назначение |
|---|---|---|---|
| POST | `/auth/register` | открытый | регистрация пользователя |
| POST | `/auth/login` | открытый | вход, возвращает JWT-токен |
| GET | `/api/data` | только с токеном | список постов |
| POST | `/api/posts` | только с токеном | создание поста |

Обязательные по заданию методы: `POST /auth/login` и `GET /api/data`. Третий метод, придуманный самостоятельно, это `POST /api/posts`. Метод `POST /auth/register` нужен, чтобы создавать пользователей с хэшированным паролем.

### POST /auth/register

Тело запроса:

```json
{"username": "alice", "password": "Str0ng-Passw0rd"}
```

Логин от 3 до 32 символов (латиница, цифры, `_`, `.`, `-`), пароль от 8 символов и не длиннее 72 байт.

| Код | Когда |
|---|---|
| 201 | пользователь создан, в ответе `id` и `username` |
| 400 | неверный формат данных |
| 409 | такой логин уже занят |

### POST /auth/login

Тело запроса такое же, как у регистрации.

Успешный ответ (200):

```json
{"access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwidXNlcm5hbWUiOiJhbGljZSIsImlhdCI6MTc5MTI3MDY5MywiZXhwIjoxNzkxMjcyNDkzfQ.47piF2sYhQExrII6KX3z5Yft8lmSch8bmcMMdqOzGow", "token_type": "Bearer", "expires_in": 1800}
```

При неверном логине или пароле возвращается 401 с одним и тем же сообщением `Неверный логин или пароль`.

### GET /api/data

Нужен заголовок `Authorization`, в котором после слова `Bearer` и пробела идёт токен из ответа `/auth/login`.

Ответ (200):

```json
{
  "user": "alice",
  "posts": [
    {"id": 1, "title": "Первый пост", "body": "Привет!", "author": "alice", "created_at": "2026-10-06 07:11:33"}
  ]
}
```

Без токена или с недействительным токеном возвращается 401.

### POST /api/posts

Нужен такой же заголовок `Authorization` с токеном, как у `GET /api/data`. Тело запроса:

```json
{"title": "Первый пост", "body": "Привет!"}
```

`title` от 1 до 200 символов, `body` от 1 до 5000 символов. В ответе 201 возвращается созданный пост, при ошибке валидации 400, без токена 401.

## Реализованные меры защиты

### Защита от SQL-инъекций (A03:2021 Injection)

Все запросы к базе выполняются через параметризованные запросы модуля `sqlite3`. Значения передаются отдельно от текста SQL через плейсхолдеры `?`, поэтому драйвер всегда воспринимает их как данные, а не как часть команды. Конкатенации строк и f-строк в SQL нет нигде в коде.

```python
user = get_db().execute(
    "SELECT id, username, password_hash FROM users WHERE username = ?", (username,)
).fetchone()
```

Если отправить в поле логина `alice' OR 1=1 --`, база будет искать пользователя с таким буквальным именем, не найдёт его, и сервер вернёт 401. В тестах это проверяют `test_login_sql_injection` и `test_sql_injection_in_post_is_stored_as_text` (строка `x'); DROP TABLE users; --` сохраняется как обычный текст, таблица остаётся на месте).

Дополнительно все входные данные проверяются на тип и длину, а логин проверяется регулярным выражением.

### Защита от XSS (A03:2021 Injection)

Все пользовательские данные, которые API возвращает в ответах (заголовок и текст поста, имя автора, имя текущего пользователя), экранируются функцией `escape()` из библиотеки MarkupSafe. Это та же функция, которую Flask и Jinja2 используют для экранирования в шаблонах. Символы `<`, `>`, `&`, `"`, `'` заменяются на HTML-сущности, поэтому даже если клиент вставит ответ в страницу через `innerHTML`, скрипт не выполнится.

```python
def serialize_post(row):
    return {
        "id": row["id"],
        "title": str(escape(row["title"])),
        "body": str(escape(row["body"])),
        "author": str(escape(row["author"])),
        "created_at": row["created_at"],
    }
```

В базе данные хранятся в исходном виде, экранирование выполняется при выводе. Пример: пост с заголовком `<script>alert(1)</script>` возвращается как `&lt;script&gt;alert(1)&lt;/script&gt;`.

Кроме этого, на каждый ответ ставятся заголовки:

| Заголовок | Значение | Зачем |
|---|---|---|
| `Content-Type` | `application/json` | браузер не рендерит ответ как HTML |
| `X-Content-Type-Options` | `nosniff` | запрещает браузеру угадывать тип содержимого |
| `Content-Security-Policy` | `default-src 'none'; frame-ancestors 'none'` | запрещает загрузку любых скриптов и ресурсов из ответа API |
| `X-Frame-Options` | `DENY` | защита от встраивания в iframe (clickjacking) |
| `Referrer-Policy` | `no-referrer` | не передавать адрес при переходах |
| `Cache-Control` | `no-store` | не кэшировать ответы с личными данными |

### Аутентификация (A07:2021 Identification and Authentication Failures)

**Хэширование паролей.** Пароли хранятся только в виде хэша bcrypt со случайной солью и cost factor 12 (2^12 итераций). Открытый пароль нигде не сохраняется и не логируется. bcrypt специально сделан медленным, поэтому перебор паролей по украденной базе обходится очень дорого. Так выглядит запись в таблице `users`:

```
1|alice|$2b$12$UbyIxb.GL905ZG4oXSxdOOhN1KpOXG40O.j65uNXuu4LARKAxqw3G
```

**JWT-токен.** После успешного входа сервер выдаёт токен, подписанный алгоритмом HS256. В токене есть:

- `sub` - id пользователя;
- `username` - логин;
- `iat` - время выдачи;
- `exp` - время истечения (по умолчанию через 30 минут).

Секрет для подписи берётся из переменной окружения `JWT_SECRET`, в коде его нет. Если переменная не задана, при старте генерируется случайный ключ длиной 64 байта.

**Middleware проверки токена.** Функция `jwt_required` в `app/auth.py` подключена к блюпринту `/api` через `before_request`. Она выполняется до любого обработчика внутри `/api`, поэтому новый защищённый эндпоинт невозможно случайно оставить открытым. Middleware:

1. берёт токен из заголовка `Authorization` (формат: слово `Bearer`, пробел, токен);
2. проверяет подпись и срок действия, причём список допустимых алгоритмов задан явно (`algorithms=["HS256"]`), так что токены с `alg: none` или с другим алгоритмом отклоняются;
3. требует наличия полей `sub`, `iat`, `exp`;
4. проверяет, что пользователь из токена существует в базе;
5. при любой ошибке возвращает 401, иначе сохраняет пользователя в `g.user`.

**Защита от перебора логинов.** На неверный логин и на неверный пароль сервер отвечает одинаково. Если пользователя нет, пароль всё равно проверяется bcrypt против заранее посчитанного фиктивного хэша, чтобы по времени ответа нельзя было понять, существует ли такой логин.

### Прочие меры

- Отладочный режим Flask выключен, сервер слушает только `127.0.0.1`.
- Ошибки возвращаются в виде коротких JSON-сообщений, без стектрейсов.
- Размер тела запроса ограничен 16 КБ (`MAX_CONTENT_LENGTH`).
- Версии зависимостей зафиксированы в `requirements.txt` и проверяются в CI на известные уязвимости.

## CI/CD pipeline

Файл: [.github/workflows/ci.yml](.github/workflows/ci.yml). Pipeline запускается при каждом push в любую ветку, при создании или обновлении pull request и вручную (`workflow_dispatch`).

| Джоб | Инструмент | Что делает |
|---|---|---|
| Tests (pytest) | pytest | запускает 18 тестов API и мер защиты |
| SAST (Bandit) | Bandit 1.9.4 | статический анализ кода в `app/` и `run.py`, падает при любой находке |
| SCA (pip-audit) | pip-audit 2.10.1 | проверка зависимостей по базе PyPI Advisory и OSV |
| SCA (OWASP Dependency-Check) | Dependency-Check 13.0.0 | проверка зависимостей по базе NVD, падает при уязвимости с CVSS 7 и выше |

Каждый сканер сохраняет отчёт как артефакт запуска (HTML, JSON или текст) и выводит краткий результат на странице запуска в разделе Summary.

### Как работает OWASP Dependency-Check

Dependency-Check запускается из официального Docker-образа `owasp/dependency-check:13.0.0` и сверяет зависимости из `requirements.txt` с базой уязвимостей NVD. Свежие версии сканера без API-ключа NVD не могут скачать базу через API, поэтому pipeline берёт её из официальных публичных JSON-фидов NVD:

1. Скрипт [.github/scripts/download_nvd_feeds.sh](.github/scripts/download_nvd_feeds.sh) по одному скачивает фиды `nvdcve-2.0-<год>.json.gz` и `nvdcve-2.0-modified.json.gz` с повторами при ошибках. Если запрашивать их параллельно, сервер NVD часто отвечает ошибкой 404.
2. Скачанные фиды кэшируются между запусками. В следующих запусках заново качаются только те файлы, у которых в `.meta` изменилась контрольная сумма.
3. Фиды раздаются локальным HTTP-сервером, и Dependency-Check получает их через параметр `--nvdDatafeed`.

Порог `--failOnCVSS 7` означает, что pipeline падает, если найдена уязвимость с оценкой CVSS 7.0 и выше.

### Разбор найденной уязвимости

При первом запуске Dependency-Check остановил pipeline на уязвимости **CVE-2025-45770** (CVSS 7.0, HIGH) в пакете PyJWT 2.15.1. Разбор показал, что это ложное срабатывание:

- в описании CVE речь идёт о библиотеке «jwt v5.4.3», ссылки ведут на PHP-библиотеку [lcobucci/jwt](https://github.com/lcobucci/jwt);
- в NVD уязвимость привязана к CPE `cpe:2.3:a:jwt_project:jwt` для версий до 5.4.3 включительно;
- Dependency-Check сопоставил PyJWT с этим CPE по слову «jwt» с уверенностью **Low**, хотя PyJWT это другой проект (CPE `pyjwt_project:pyjwt`), а установленная версия 2.15.1;
- сама CVE в NVD помечена как оспоренная (disputed).

Порог проверки я не снижал. Вместо этого добавил файл [dependency-check-suppressions.xml](dependency-check-suppressions.xml), который отвязывает от PyJWT только чужой CPE `jwt_project:jwt`. Уязвимости, привязанные к настоящему CPE PyJWT, по-прежнему будут найдены, и pipeline упадёт. После этого Dependency-Check показывает 0 уязвимостей и 1 подавленное ложное срабатывание.

Ещё одно исправление по результатам SAST: Bandit выдал предупреждение B106 (hardcoded password) на строку `token_type="Bearer"`. Это тоже ложное срабатывание, но вместо комментария `# nosec` строка вынесена в константу `AUTH_SCHEME`, которая теперь используется и при выдаче токена, и в middleware.

### Ссылки на запуски

- Все запуски: https://github.com/semchik200001/secure-rest-api/actions
- Успешные запуски в ветке main: https://github.com/semchik200001/secure-rest-api/actions/workflows/ci.yml?query=branch%3Amain+is%3Asuccess

## Результаты проверок

Скриншоты сделаны по запуску [#5](https://github.com/semchik200001/secure-rest-api/actions/runs/37434536022). Логи шагов выгружены из GitHub Actions командой `gh run view --log`, HTML-отчёт Dependency-Check взят из артефактов этого запуска.

### Запуск pipeline в GitHub Actions

Все четыре джоба завершились успешно, отчёты сохранены как артефакты.

![Запуск pipeline](docs/screenshots/01-pipeline.png)

### SAST: Bandit

Проверено 250 строк кода, проблем не найдено.

![Отчёт Bandit](docs/screenshots/02-bandit.png)

### SCA: pip-audit

Известных уязвимостей в зависимостях нет (проверены все 9 пакетов, включая транзитивные).

![Отчёт pip-audit](docs/screenshots/03-pip-audit.png)

### SCA: OWASP Dependency-Check

Лог сканирования:

![Лог Dependency-Check](docs/screenshots/04-dependency-check-log.png)

HTML-отчёт: просканировано 5 зависимостей, уязвимых 0, найдено 0, подавлено 1 ложное срабатывание.

![Отчёт Dependency-Check](docs/screenshots/05-dependency-check-report.png)

### Тесты

![Результат pytest](docs/screenshots/06-pytest.png)

## Тестирование

### Автотесты

В `tests/test_api.py` 18 тестов. Они проверяют:

- регистрацию, вход и получение токена;
- что пароль в базе хранится как хэш bcrypt;
- отказ при неверном пароле и одинаковое сообщение для неверного логина и пароля;
- отказ без токена, с мусорным токеном, с токеном, подписанным чужим ключом, с токеном `alg: none` и с просроченным токеном;
- экранирование XSS-нагрузки в ответах;
- что SQL-инъекции в логине и в тексте поста не срабатывают;
- валидацию входных данных и заголовки безопасности.

### Проверка через curl

Регистрация:

```
$ curl -s -X POST http://127.0.0.1:8000/auth/register -H 'Content-Type: application/json' -d '{"username": "alice", "password": "Str0ng-Passw0rd"}'
{"id":1,"username":"alice"}
```

Вход с неверным паролем:

```
$ curl -s -X POST http://127.0.0.1:8000/auth/login -H 'Content-Type: application/json' -d '{"username": "alice", "password": "wrong-password"}'
{"error":"Неверный логин или пароль"}
```

Вход с правильным паролем:

```
$ curl -s -X POST http://127.0.0.1:8000/auth/login -H 'Content-Type: application/json' -d '{"username": "alice", "password": "Str0ng-Passw0rd"}'
{"access_token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwidXNlcm5hbWUiOiJhbGljZSIsImlhdCI6MTc5MTI3MDY5MywiZXhwIjoxNzkxMjcyNDkzfQ.47piF2sYhQExrII6KX3z5Yft8lmSch8bmcMMdqOzGow","expires_in":1800,"token_type":"Bearer"}
```

Токен из ответа на вход сохраняется в переменную `TOKEN`, она используется в запросах ниже:

```
$ TOKEN=$(curl -s -X POST http://127.0.0.1:8000/auth/login -H 'Content-Type: application/json' -d '{"username": "alice", "password": "Str0ng-Passw0rd"}' | python3 -c "import sys, json; print(json.load(sys.stdin)['access_token'])")
```

Запрос данных без токена:

```
$ curl -s -i http://127.0.0.1:8000/api/data
HTTP/1.1 401 UNAUTHORIZED
Content-Type: application/json
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Content-Security-Policy: default-src 'none'; frame-ancestors 'none'
Referrer-Policy: no-referrer
Cache-Control: no-store

{"error":"Требуется авторизация"}
```

Запрос с недействительным токеном:

```
$ curl -s http://127.0.0.1:8000/api/data -H 'Authorization: Bearer invalid.token.here'
{"error":"Недействительный токен"}
```

Создание поста с XSS-нагрузкой:

```
$ curl -s -X POST http://127.0.0.1:8000/api/posts -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d '{"title": "<script>alert(1)</script>", "body": "<img src=x onerror=alert(1)>"}'
{"author":"alice","body":"&lt;img src=x onerror=alert(1)&gt;","created_at":"2026-10-06 07:11:33","id":2,"title":"&lt;script&gt;alert(1)&lt;/script&gt;"}
```

Получение данных с токеном:

```
$ curl -s http://127.0.0.1:8000/api/data -H "Authorization: Bearer $TOKEN"
{"posts":[{"author":"alice","body":"&lt;img src=x onerror=alert(1)&gt;","created_at":"2026-10-06 07:11:33","id":2,"title":"&lt;script&gt;alert(1)&lt;/script&gt;"},{"author":"alice","body":"Привет!","created_at":"2026-10-06 07:11:33","id":1,"title":"Первый пост"}],"user":"alice"}
```

Попытка SQL-инъекции в логине:

```
$ curl -s -X POST http://127.0.0.1:8000/auth/login -H 'Content-Type: application/json' -d '{"username": "alice'\'' OR 1=1 --", "password": "x"}'
{"error":"Неверный логин или пароль"}
```
