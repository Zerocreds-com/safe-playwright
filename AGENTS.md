# Repository instructions

AGENTS.md — короткая точка входа. Основные инструкции, команды, среды и порядок deploy описаны в [README.md](README.md); здесь не дублируются.

## Credentials

Секреты не печатаются и не попадают в файлы. Для GitHub и Cloudflare используйте соответствующие Keychain entries из общих root AGENTS.md/README документации; для доступа по умолчанию — default PAT `github.com`/`kobzevvv`.

## Sandbox / deploy

Порядок sandbox, проверок, deploy и rollback берётся из README.md и referenced docs/workflows.
После merge нельзя считать задачу завершённой без deploy/verify по этому порядку.
Самые опасные изменения — запреты/ограничения прав; они требуют собранного evidence.
