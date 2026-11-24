# BionicPRO

Проектная работа 9 спринта курса "Архитектор ПО": безопасность входа, отчеты по работе протезов, снижение нагрузки на БД.

## Задание 1. Повышение безопасности системы

- Вход через Keycloak по authorization code flow с PKCE.
- Токены IdP не передаются фронтенду: их получает и хранит сервис bionicpro-auth, браузер получает только cookie сессии с флагами HttpOnly и Secure. Сессия ротируется при каждом обращении к защищенным ресурсам, access_token обновляется через refresh_token.
- Пользователи представительства в другой стране аутентифицируются по LDAP без копирования их персональных данных в Keycloak, группы LDAP отображаются на роли realm.
- Обязательный OTP (Google Authenticator, FreeOTP) для всех пользователей.
- Вход через Яндекс ID (Identity Brokering) с запросом согласия на использование профиля.

Архитектура: `diagrams/bionicpro-c4-security.drawio`, решения и разбор противоречий задания: `docs/decisions.md`, проверка: `docs/checks.md`.

## Структура репозитория

| Путь | Назначение |
| --- | --- |
| `bionicpro-auth/` | Сервис входа и сессий (Python, FastAPI) и его тесты |
| `config/defaults.toml` | Параметры по умолчанию стенда |
| `diagrams/` | Диаграммы C4 в draw.io |
| `docs/` | Решения и инструкции по проверке |
| `frontend/` | Веб-приложение отчетов (React) и конфигурация nginx |
| `keycloak/` | Образ Keycloak с провайдером Яндекс ID, realm для импорта и экспорт после настройки |
| `ldap/` | Пользователи и группы каталога представительства |
| `tests/` | Тесты согласованности конфигураций и диаграмм |

## Запуск

```bash
docker compose up -d --build
```

Приложение: http://localhost:3000, Keycloak: http://localhost:8080. Перед первым запуском нужен файл `.env` с данными приложения Яндекс ID, порядок описан в `docs/checks.md`.

## Тесты

```bash
pip install -r tests/requirements.txt -r bionicpro-auth/requirements-dev.txt
pytest -q
(cd bionicpro-auth && pytest -q)
```
