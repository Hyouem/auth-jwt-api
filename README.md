# Auth JWT API

API REST de autenticacao e autorizacao com Java 25, Spring Boot 4.1.2, Spring Security, JWT HS256, BCrypt, PostgreSQL 17, Flyway, JPA e JUnit.

## Endpoints

| Metodo | Endpoint | Acesso |
| --- | --- | --- |
| POST | `/api/auth/register` | Publico; cria `USER` |
| POST | `/api/auth/login` | Publico; retorna `accessToken`, `tokenType` e `expiresIn` |
| GET | `/api/users/me` | Bearer JWT valido |
| GET | `/api/admin/status` | Bearer JWT com papel `ADMIN` |

Cadastro:

```json
{
  "email": "usuario@example.com",
  "password": "SenhaForte123!"
}
```

Login: mesmo JSON. A resposta inclui um token Bearer com expiracao de 900 segundos.

## Execucao local

Requer Java 25, Docker, PostgreSQL 17 e Maven Wrapper.

Configure as variaveis de ambiente:

- DB_HOST
- DB_PORT
- DB_NAME
- DB_USER
- DB_PASSWORD
- JWT_SECRET

JWT_SECRET deve conter 32 bytes aleatorios codificados em Base64.

Nao publique a chave.

```powershell
.\mvnw.cmd clean verify
.\mvnw.cmd spring-boot:run
```

Banco local: localhost:5433/auth_jwt_db.

O Flyway aplica a migracao V1__create_users.sql.

## Seguranca

- Senhas armazenadas com BCrypt.
- Hash de senha nunca retornado nas respostas.
- JWT HS256 com assinatura, emissor e validade verificados.
- Cadastro publico cria exclusivamente usuarios USER.
- HTTP 401 para ausencia de autenticacao ou token invalido.
- HTTP 403 para papel insuficiente.
- ADMIN deve ser provisionado por processo administrativo confiavel.

## Limitacoes

Papeis no JWT permanecem validos ate a expiracao de 15 minutos,
mesmo que o papel do usuario mude no banco.

Para producao, avaliar revogacao de tokens, rotacao de chaves,
rate limiting e politica de refresh tokens.

## CI

GitHub Actions executa Maven clean verify com PostgreSQL 17
em servico isolado e credenciais exclusivas de teste.