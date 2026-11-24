# Проверка решения

## Задание 1. Повышение безопасности системы

### 1. Автотесты

Нужен Python 3.11 или новее.

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r tests/requirements.txt -r bionicpro-auth/requirements-dev.txt
pytest -q
(cd bionicpro-auth && pytest -q)
```

Ожидаемый результат: обе команды завершаются строкой `passed` без `failed` и `error`.

Что проверяют тесты:

- `tests/` - значения в `keycloak/realm-export.json`, `docker-compose.yaml`, `keycloak/Dockerfile`, `frontend/nginx.conf` совпадают с `config/defaults.toml`; во фронтенде нет работы с токенами и Keycloak; ldif согласован с ролями realm; элементы и стрелки диаграммы соответствуют легенде.
- `bionicpro-auth/tests/` - PKCE S256, проверка state и nonce, флаги cookie, отсутствие токенов в ответах и в открытом виде в Redis, ротация session id и окно grace, обновление access_token через refresh_token, завершение сессии при отклоненном refresh_token, проксирование с Bearer, logout с проверкой Origin.

### 2. Приложение Яндекс ID

1. Создать приложение на https://oauth.yandex.ru/client/new, платформа "Веб-сервисы".
2. Redirect URI: `http://localhost:8080/realms/reports-realm/broker/yandex/endpoint`.
3. Доступы: "Доступ к адресу электронной почты", "Доступ к логину, имени и фамилии, полу".
4. В корне репозитория создать файл `.env` (он в `.gitignore`):

```bash
cat > .env <<'EOF'
YANDEX_CLIENT_ID=<ClientID приложения>
YANDEX_CLIENT_SECRET=<Client secret приложения>
TOKEN_ENCRYPTION_KEY=<результат команды ниже>
EOF
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

### 3. Запуск стенда

Realm импортируется только в пустую БД Keycloak, поэтому перед проверкой старые данные удаляются.

```bash
docker compose down
rm -rf postgres-keycloak-data
docker compose up -d --build
docker compose ps
```

Ожидаемый результат: сервисы `keycloak_db`, `keycloak`, `openldap`, `redis`, `bionicpro-auth`, `frontend` в состоянии `running`.

```bash
docker compose logs keycloak | grep -E "imported|Listening"
curl -s http://localhost:8080/realms/reports-realm/.well-known/openid-configuration | python3 -m json.tool | grep -E '"issuer"|code_challenge'
curl -s http://localhost:8000/health
```

Ожидаемый результат: в логе строка `Realm 'reports-realm' imported`; issuer `http://localhost:8080/realms/reports-realm`, в `code_challenge_methods_supported` есть `S256`; health возвращает `{"status":"ok"}`.

Если сборка образа Keycloak падает на загрузке `keycloak-russian-providers`, проверить наличие версии из `config/defaults.toml` на https://repo1.maven.org/maven2/ru/playa/keycloak/keycloak-russian-providers/.

### 4. Вход пользователя представительства (LDAP + OTP)

1. Открыть http://localhost:3000 в окне инкогнито, нажать Login.
2. Ввести `john.doe` / `password` (пользователь из `ldap/config.ldif`).
3. Ожидаемый результат: Keycloak требует настроить OTP и показывает QR-код. Отсканировать его в Google Authenticator или FreeOTP, ввести код.
4. Ожидаемый результат: экран согласия BionicPRO на доступ к профилю. Нажать Yes.
5. Ожидаемый результат: возврат на http://localhost:3000, надпись `Signed in as john.doe`.
6. Выйти (Logout), снова войти: после пароля Keycloak запрашивает одноразовый код. С неверным кодом вход не выполняется.

Роли из групп LDAP:

```bash
docker compose exec openldap ldapsearch -x -H ldap://localhost -b ou=Groups,dc=example,dc=com -D cn=admin,dc=example,dc=com -w admin member
```

В приложении после входа запрос `GET /auth/session` (DevTools, Network) возвращает у `john.doe` роль `prothetic_user`, у `jane.smith` роль `user`.

Данные представительства не импортированы в Keycloak: в админке http://localhost:8080/admin (admin / admin), realm `reports-realm`, Users, поиск `*` показывает пользователя `john.doe` с пометкой федерации, а в таблице БД его ФИО нет:

```bash
docker compose exec keycloak_db psql -U keycloak_user -d keycloak_db -c "select username from user_entity where realm_id='reports-realm';"
```

Ожидаемый результат: в списке только локальные пользователи realm, без `john.doe`, `jane.smith`, `alex.johnson`.

### 5. PKCE и отсутствие токенов в браузере

1. DevTools, Network, включить Preserve log, войти заново.
2. Запрос `GET /auth/login` отвечает 302 на `.../protocol/openid-connect/auth` с параметрами `code_challenge` и `code_challenge_method=S256`.
3. Запрос без PKCE отклоняется Keycloak:

```bash
curl -s -o /dev/null -w "%{http_code} %{redirect_url}\n" "http://localhost:8080/realms/reports-realm/protocol/openid-connect/auth?client_id=bionicpro-auth&response_type=code&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fauth%2Fcallback&scope=openid"
```

Ожидаемый результат: 302 на redirect URI с `error=invalid_request` и `error_description=Missing+parameter%3A+code_challenge_method`. С `code_challenge_method=plain` Keycloak тоже отвечает `invalid_request`: разрешен только метод из `config/defaults.toml`.

4. Application, Cookies, http://localhost:3000: есть только `bionicpro_session` с отметками HttpOnly и Secure. Local Storage и Session Storage пустые. Ни в одном ответе `/auth/*` нет `access_token` и `refresh_token`.

### 6. Ротация сессии и обновление токена

1. Запомнить значение `bionicpro_session`, обновить страницу: значение cookie изменилось, ответ `GET /auth/session` содержит заголовок `Set-Cookie` с новым id.
2. Подождать дольше времени жизни access_token и обновить страницу.

```bash
docker compose logs bionicpro-auth | grep -E "session created|access token refreshed"
```

Ожидаемый результат: после ожидания появляется строка `access token refreshed`, пользователь остается в системе.

3. Токены в Redis зашифрованы, ключи - хеши session id:

```bash
docker compose exec redis redis-cli --scan --pattern 'bionicpro:session:*'
docker compose exec redis sh -c 'redis-cli --scan --pattern "bionicpro:session:*" | head -1 | xargs redis-cli GET'
```

Ожидаемый результат: значения полей `access_token` и `refresh_token` начинаются с `gAAAA` (Fernet), JWT вида `eyJ...` в открытом виде нет.

### 7. Вход через Яндекс ID

1. На http://localhost:3000 нажать Login with Yandex ID.
2. Ожидаемый результат: страница Яндекса с запросом доступа к профилю, затем экран Keycloak с обязательной настройкой OTP, затем экран согласия BionicPRO, затем возврат в приложение с `Signed in as <логин Яндекса>`.
3. В админке Keycloak, Users, у пользователя вкладка Identity provider links содержит `yandex`, вкладка Attributes содержит `yandex_id`, `yandex_login`.

### 8. Экспорт realm

```bash
TOKEN=$(curl -s -d client_id=admin-cli -d username=admin -d password=admin -d grant_type=password \
  http://localhost:8080/realms/master/protocol/openid-connect/token | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')
curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8080/admin/realms/reports-realm/partial-export?exportClients=true&exportGroupsAndRoles=true" \
  | python3 -m json.tool --no-ensure-ascii > keycloak/keycloak-results-export.json
grep -o '"[*]\{10\}"' keycloak/keycloak-results-export.json | wc -l
```

Ожидаемый результат: файл создан, секреты клиентов, LDAP и Яндекса замаскированы: команда выводит ненулевое число замаскированных значений.
