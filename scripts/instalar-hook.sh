#!/bin/sh
# Instala o hook post-commit que aciona o Agente de Segurança após cada commit.
# Uso (a partir da pasta do agente):  sh scripts/instalar-hook.sh [caminho-do-repositorio]
# O hook roda em segundo plano e NUNCA bloqueia o commit.
set -e

AGENTE_DIR=$(cd "$(dirname "$0")/.." && pwd)
REPO_DIR=${1:-$(git -C "$AGENTE_DIR" rev-parse --show-toplevel)}
HOOK="$REPO_DIR/.git/hooks/post-commit"

if [ ! -d "$REPO_DIR/.git" ]; then
  echo "Repositório Git não encontrado em $REPO_DIR" >&2
  exit 1
fi

if [ -f "$HOOK" ] && ! grep -q "Agente de Segurança" "$HOOK"; then
  cp "$HOOK" "$HOOK.backup"
  echo "Hook existente salvo em $HOOK.backup"
fi

cat > "$HOOK" <<EOF
#!/bin/sh
# Agente de Segurança — análise consultiva do último commit (não bloqueia)
REPO="\$(git rev-parse --show-toplevel)"
mkdir -p "\$REPO/relatorios-seguranca"
( cd "$AGENTE_DIR" && npx --no-install tsx src/cli.ts "\$REPO" --ultimo-commit \\
    > "\$REPO/relatorios-seguranca/ultimo-commit.log" 2>&1 ) &
echo "[Agente de Segurança] análise iniciada em segundo plano — veja relatorios-seguranca/ultimo.md"
exit 0
EOF
chmod +x "$HOOK"
echo "Hook instalado em $HOOK"
