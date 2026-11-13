#!/usr/bin/env bash
# =============================================================================
#  recon_high_end.sh
#  Pipeline de recon "high-end" para Bug Bounty — DB-first, paralelo e limpo.
#
#  FILOSOFIA
#    Este script NÃO caça bugs. Ele produz artefatos cirúrgicos para que o
#    agente (via Caido MCP) valide manualmente: IDOR, race condition, mass
#    assignment, authz quebrada. Zero scanning cego (sem nuclei/dalfox em
#    live.txt). O objetivo é cobertura + sinal, não ruído.
#
#  SAÍDA
#    /home/hack/docs/<target>/
#      subdomains.txt         → inventário final de hosts
#      live.jsonl / live.txt  → hosts vivos (JSON estruturado + URLs)
#      endpoints.txt          → crawl + histórico + JS, dedup com uro
#      js_files.txt           → arquivos JS para análise
#      js_endpoints.txt       → rotas extraídas via jsluice (+ sourcemaps)
#      js_secrets.jsonl       → segredos (jsluice + trufflehog)
#      params_*.txt           → classes de parâmetros (gf + fallback)
#      arjun_params.txt       → parâmetros ocultos
#      high_value_targets.txt → TOP alvos de dinheiro/lógica (score ordenado)
#      SUMMARY.md             → relatório da execução
#      logs/                  → logs por ferramenta com timestamp Unix
#
#    docs/_batch-<unix_ts>/SUMMARY.md → resumo do lote (multi-target)
#
#  USO
#    ./scripts/recon_high_end.sh                        menu interativo
#    ./scripts/recon_high_end.sh alvo.com               um alvo
#    ./scripts/recon_high_end.sh '*.a.com' b.com        vários alvos
#    ./scripts/recon_high_end.sh --file lista.txt       lista de alvos
#
#    No menu: adicionar/importar/remover targets, rodar todos ou selecionados.
#    A lista persistida fica em /home/hack/targets/recon_targets.txt
#    Wildcard é normalizado: *.example.com → example.com
#    Alvos do lote rodam em SEQUÊNCIA (um por vez) e subdomínios já cobertos
#    por um alvo-pai da lista são removidos (dedupe).
#
#    Banner ASCII (branco): /home/hack/scripts/banner.txt
#
#  PERFIS
#    default (rápido)  ports=quick (top 100, -ec) | katana=120 hosts em chunks
#                      de 25, sem -jsl/-aff | histórico por domínio (1 chamada)
#    --deep            ports=full (top 1000) | katana=todos | depth 3 | jsl/aff
#                      off (RAM) | bruteforce ligado | mais JS/arjun
#
#    Tudo é ajustável por env (PORTS_MODE, KATANA_MAX_HOSTS, KATANA_CHUNK,
#    KATANA_DEPTH, KATANA_JSLUICE, KATANA_AFF, HISTORY_PER_HOST, MAX_JS...).
#
#  UI (menu estilo Berserk)
#    Tema em /home/hack/targets/recon_ui.conf: berserk | matrix | cyber | mono
#    No menu: t troca tema · a add · i import · x remover · r rodar · s seleção
#              o opções · p pastas · q sair
#    Cards de pré-voo/resultado aparecem só em TTY (não poluem logs).
#
#  AUTH (opcional, nunca hardcoded)
#    /home/hack/targets/auth_headers.txt   (uma header por linha)
#      Cookie: __Host-sessionid=...
#      Authorization: Bearer ...
#
#  TOKEN GITHUB (opcional, para github-subdomains)
#    /home/hack/targets/github_token   (1 token)   ou   export GITHUB_TOKEN=...
#
#  NOTA DE ESCOPO: rode apenas em ativos autorizados. Este script faz
#  requisições HTTP reais; o Portão Humano do AGENTS.md continua valendo.
# =============================================================================
set -euo pipefail

VERSION="1.2.0"
SELF="$(basename "$0")"

# ── Configuração (sobrescreva por env) ───────────────────────────────────────
DOCS_ROOT="${DOCS_ROOT:-/home/hack/docs}"
DB_PATH="${DB_PATH:-/home/hack/opencode-pentester/db/findings.db}"
TARGETS_FILE="${TARGETS_FILE:-/home/hack/targets/recon_targets.txt}"
BANNER_FILE="${BANNER_FILE:-/home/hack/scripts/banner.txt}"
AUTH_FILE="${AUTH_FILE:-/home/hack/targets/auth_headers.txt}"
GH_TOKEN_FILE="${GH_TOKEN_FILE:-/home/hack/targets/github_token}"
CHAOS_KEY_FILE="${CHAOS_KEY_FILE:-/home/hack/targets/chaos_key}"
SCOPE_FILE="${SCOPE_FILE:-/home/hack/targets/scope.md}"
RESOLVERS="${RESOLVERS:-/home/hack/wordlists/resolvers/resolvers.txt}"
DNS_WORDLIST="${DNS_WORDLIST:-/home/hack/wordlists/SecLists/Discovery/DNS/subdomains-top1million-110000.txt}"

THREADS="${THREADS:-10}"                 # paralelismo global
MAX_PERMUTATIONS="${MAX_PERMUTATIONS:-6000}"   # permutações geradas/ resolvidas
PERM_INPUT="${PERM_INPUT:-1500}"               # hosts de entrada do alterx
MAX_JS="${MAX_JS:-3000}"                 # teto de arquivos JS baixados
MAX_ARJUN="${MAX_ARJUN:-15}"             # teto de origins para arjun
PORTS_MODE="${PORTS_MODE:-quick}"        # none | quick (top 100) | full (top 1000)
NAABU_TOP_PORTS="${NAABU_TOP_PORTS:-1000}"     # usado quando PORTS_MODE=full
NAABU_EXCLUDE="${NAABU_EXCLUDE:-22,23,3389}"
HTTP_TIMEOUT="${HTTP_TIMEOUT:-8}"
KATANA_DEPTH="${KATANA_DEPTH:-3}"
KATANA_FS="${KATANA_FS:-fqdn}"
KATANA_HEADLESS="${KATANA_HEADLESS:-0}"
KATANA_CHUNK="${KATANA_CHUNK:-25}"       # hosts por processo (evita OOM)
KATANA_MAX_HOSTS="${KATANA_MAX_HOSTS:-120}"  # 0 = todos
KATANA_JSLUICE="${KATANA_JSLUICE:-0}"    # -jsl consome muita RAM
KATANA_AFF="${KATANA_AFF:-0}"            # automatic form fill
KATANA_FSU="${KATANA_FSU:-1}"            # filtra URLs parecidas (IDs numéricos)
KATANA_CHUNK_TIMEOUT="${KATANA_CHUNK_TIMEOUT:-240}"
KATANA_MAX_URLS_PER_CHUNK="${KATANA_MAX_URLS_PER_CHUNK:-20000}"
# hosts de conteúdo/estático fora do crawl (economiza horas e ruído)
CRAWL_EXCLUDE="${CRAWL_EXCLUDE:-cdn|static|img[0-9]*|images|assets|media|files|downloads?|fonts|blog|backend\.blog|www\.blog|building|novidades|estagio|comunidade|community|help|suporte|ajuda|careers|carreiras|newsroom|imprensa|status|trust|privacidade|legal|termos}"
# wayback está bloqueado nesta rede; commoncrawl/urlscan funcionam
GAU_PROVIDERS="${GAU_PROVIDERS:-commoncrawl,urlscan}"
HISTORY_PER_HOST="${HISTORY_PER_HOST:-0}" # 1 = um processo por host (lento)
SKIP_CHAOS="${SKIP_CHAOS:-0}"
SUBFINDER_ALL="${SUBFINDER_ALL:-0}"
SUBFINDER_RECURSIVE="${SUBFINDER_RECURSIVE:-0}"
SUBFINDER_MAX_TIME="${SUBFINDER_MAX_TIME:-3}"
SUBFINDER_TIMEOUT="${SUBFINDER_TIMEOUT:-10}"

TS="$(date +%s)"
TARGET=""
FORCE=0
FRESH=0
DEEP=0
PROFILE_LABEL="default"
SKIP_BRUTE=1
SKIP_PORTS=0
SKIP_HISTORY=0
SKIP_ARJUN=0
DB_ENABLED=1
PHASE_RC=0
PHASE_N=0
PHASE_TOTAL=7

# ── Cores (só quando TTY) ────────────────────────────────────────────────────
if [[ -t 2 ]]; then
  C_OK=$'\033[32m'; C_WARN=$'\033[33m'; C_ERR=$'\033[31m'; C_HDR=$'\033[36m'; C_RST=$'\033[0m'
else
  C_OK=""; C_WARN=""; C_ERR=""; C_HDR=""; C_RST=""
fi

usage() {
  cat <<EOF
${SELF} v${VERSION} — recon high-end para bug bounty

USO
  ${SELF}                        menu interativo (gerencia a lista de targets)
  ${SELF} <target> [target...]   executa direto (1 ou vários alvos)
  ${SELF} --file lista.txt       executa todos os alvos do arquivo
  ${SELF} --menu                 força o menu interativo

ARGUMENTOS
  <target>              domínio/host. Aceita wildcard: *.example.com → example.com
                        Aceita http(s)://, vírgula e espaço como separador.

OPÇÕES
  --threads N           paralelismo por alvo (default: ${THREADS})
  --fresh               apaga o diretório de saída antes de rodar
  --force               ignora o scope gate (confirme autorização)
  --plan                valida/normaliza/deduplica alvos e mostra o plano (sem requests)
  --check-keys          testa token GitHub e key do chaos (sem recon) e sai
  --file F              lê alvos de F (1 por linha, # comentário, wildcard ok)
  --skip-brute          pula shuffledns bruteforce (default: já pulado)
  --brute               liga o bruteforce DNS (110k wordlist, lento)
  --skip-ports          pula naabu (probe HTTP direto nos hostnames)
  --ports MODE          none | quick (top 100, default) | full (top 1000)
  --skip-history        pula waybackurls/gau
  --skip-arjun          pula descoberta de parâmetros ocultos
  --skip-chaos          não usa chaos mesmo com key válida
  --deep                cobertura total: todos os hosts no katana, depth 3,
                        ports full, bruteforce on, 20k perm, 6k JS (jsl/aff off
                        por segurança de RAM; religue em [7] 14/15)
  --katana-hosts N      teto de hosts no crawl (0 = todos)
  --katana-depth N      profundidade do crawl
  --katana-chunk N      hosts por processo do katana (memória)
  -h, --help            esta ajuda

MULTI-TARGET
  Alvos são executados em sequência (1 por vez) para não saturar o alvo.
  A lista do menu fica em: ${TARGETS_FILE}
  Subdomínios cobertos por um alvo-pai da mesma lista são removidos (dedupe).

MENU [7] OPÇÕES
  Controla tudo: perfil DEEP (liga/desliga), threads, skip-brute, ports mode,
  katana hosts/depth/chunk, skip-history, skip-arjun, skip-chaos, fresh, force.
  A linha de status abaixo da lista mostra o perfil ativo antes de rodar.

ENV
  THREADS MAX_PERMUTATIONS MAX_JS MAX_ARJUN NAABU_TOP_PORTS NAABU_EXCLUDE
  KATANA_DEPTH KATANA_FS KATANA_HEADLESS AUTH_FILE GH_TOKEN_FILE DB_PATH DOCS_ROOT
  TARGETS_FILE BANNER_FILE CHAOS_KEY_FILE SKIP_CHAOS
  SUBFINDER_ALL SUBFINDER_RECURSIVE SUBFINDER_MAX_TIME SUBFINDER_TIMEOUT
  PORTS_MODE KATANA_CHUNK KATANA_MAX_HOSTS KATANA_DEPTH KATANA_JSLUICE
  KATANA_AFF KATANA_FSU KATANA_CHUNK_TIMEOUT KATANA_MAX_URLS_PER_CHUNK
  HISTORY_PER_HOST MAX_JS MAX_ARJUN CRAWL_EXCLUDE GAU_PROVIDERS

EXEMPLO
  ${SELF}                                  # abre o menu
  ${SELF} '*.alasco.de' app.alasco.rocks
  ${SELF} --file targets/recon_targets.txt --threads 20
EOF
}

_logfile() {
  local f="${LOG:-}"
  [[ -n "$f" && -d "${f%/*}" ]] || return 0
  printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*" >> "$f" 2>/dev/null || true
}
log()  { _logfile "$*"; printf '%s[%s]%s %s\n' "$C_HDR" "$(date +%H:%M:%S)" "$C_RST" "$*" >&2; }
warn() { _logfile "! $*"; printf '%s[%s] !%s %s\n' "$C_WARN" "$(date +%H:%M:%S)" "$C_RST" "$*" >&2; }
die()  { _logfile "x $*"; printf '%s[%s] x%s %s\n' "$C_ERR" "$(date +%H:%M:%S)" "$C_RST" "$*" >&2; exit 1; }

# Banner (ASCII em branco). Fica em arquivo separado para trocar sem editar código.
print_banner() {
  [[ -t 1 ]] || return 0
  printf '%s' "${UI_TXT:-$'\033[97m'}"
  if [[ -r "$BANNER_FILE" ]]; then
    cat "$BANNER_FILE"
  else
    printf '  recon_high_end v%s\n' "$VERSION"
  fi
  printf '%s' "${UI_RST:-$'\033[0m'}"
}

have() { command -v "$1" >/dev/null 2>&1; }

count() { if [[ -f "$1" ]]; then wc -l < "$1" | tr -d ' '; else echo 0; fi; }

# Preserva artefatos de execuções anteriores (ex: git pull do GH Actions)
backup_existing() {
  local f bak="$LOGS/backup-${TS}" moved=0
  for f in subdomains.txt endpoints.txt live.txt live.jsonl js_files.txt \
           high_value_targets.txt params_all.txt SUMMARY.md; do
    if [[ -s "$OUT/$f" ]]; then
      mkdir -p "$bak"
      mv -f "$OUT/$f" "$bak/" 2>/dev/null && moved=1
    fi
  done
  (( moved )) && log "backup: artefatos anteriores movidos para ${bak}"
  return 0
}

# Copia artefato relevante para logs/<tool>-<ts>.txt (contrato de artefatos)
stamp() {
  local f="$1" tool="$2"
  [[ -n "${LOGS:-}" && -s "$f" ]] || return 0
  cp -f "$f" "$LOGS/${tool}-${TS}.txt" 2>/dev/null || true
}

# ── Fases ────────────────────────────────────────────────────────────────────
run_phase() {
  local name="$1"; shift
  local t0=$SECONDS rc=0
  PHASE_N=$((PHASE_N + 1))
  log "▶ FASE [${PHASE_N}/${PHASE_TOTAL}]: ${name}"
  "$@" || rc=$?
  local dur=$(( SECONDS - t0 ))
  PHASE_RC=$rc
  if (( rc == 0 )); then
    log "✔ ${name} concluída em ${dur}s"
  else
    warn "${name} terminou com rc=${rc} em ${dur}s — artefatos parciais preservados"
  fi
  db_log "$name" "pipeline" "$([[ $rc -eq 0 ]] && echo ok || echo partial)" "" "rc=${rc}" "$dur"
  return 0
}

# ── Banco de dados (DB-first) ────────────────────────────────────────────────
sql_esc() { printf '%s' "${1//\'/\'\'}"; }

db_init() {
  if ! have sqlite3; then
    warn "sqlite3 ausente: logging no DB desativado"
    DB_ENABLED=0
    return 0
  fi
  mkdir -p "$(dirname "$DB_PATH")"
  if sqlite3 "$DB_PATH" "CREATE TABLE IF NOT EXISTS recon_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target TEXT NOT NULL,
        phase TEXT NOT NULL,
        tool TEXT,
        status TEXT,
        artifact TEXT,
        detail TEXT,
        duration_s INTEGER DEFAULT 0,
        created_at TEXT DEFAULT (datetime('now'))
      );" 2>/dev/null; then
    log "DB: recon_logs pronto em ${DB_PATH}"
  else
    warn "DB: falha ao inicializar recon_logs — logging desativado"
    DB_ENABLED=0
  fi
}

db_log() {
  (( DB_ENABLED )) || return 0
  local phase tool status artifact detail dur
  phase="$(sql_esc "$1")"; tool="$(sql_esc "$2")"; status="$(sql_esc "$3")"
  artifact="$(sql_esc "${4:-}")"; detail="$(sql_esc "${5:-}")"; dur="${6:-0}"
  sqlite3 "$DB_PATH" \
    "INSERT INTO recon_logs (target,phase,tool,status,artifact,detail,duration_s)
     VALUES ('$(sql_esc "$TARGET")','$phase','$tool','$status','$artifact','$detail',${dur:-0});" \
    2>/dev/null || true
}

# ── Auth headers ─────────────────────────────────────────────────────────────
HDRS=()
HDR_FLAGS=()
HDR_BLOB=""
AUTH_RC=""
HV_AWK=""

cleanup() {
  [[ -n "$AUTH_RC" && -f "$AUTH_RC" ]] && rm -f "$AUTH_RC"
  [[ -n "$HV_AWK" && -f "$HV_AWK" ]] && rm -f "$HV_AWK"
  return 0
}
trap cleanup EXIT

load_auth() {
  HDRS=(); HDR_FLAGS=(); HDR_BLOB=""

  # Cookies nunca são escritos em docs/ (docs é versionado): arquivo temporário 600.
  mkdir -p /tmp/opencode
  AUTH_RC="$(mktemp /tmp/opencode/recon-curlrc-XXXXXX)"
  chmod 600 "$AUTH_RC"
  : > "$AUTH_RC"

  if [[ ! -f "$AUTH_FILE" ]]; then
    log "auth: ${AUTH_FILE} ausente → crawl anônimo"
    return 0
  fi

  local line
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%$'\r'}"
    [[ -z "${line//[[:space:]]/}" ]] && continue
    [[ "$line" == \#* ]] && continue
    HDRS+=("$line")
  done < "$AUTH_FILE"

  if (( ${#HDRS[@]} == 0 )); then
    log "auth: arquivo presente mas sem headers válidos"
    return 0
  fi

  local h esc
  for h in "${HDRS[@]}"; do
    esc="${h//\"/\\\"}"
    printf 'header = "%s"\n' "$esc" >> "$AUTH_RC"
    HDR_FLAGS+=(-H "$h")
    HDR_BLOB+="${h}"$'\n'
  done
  chmod 400 "$AUTH_RC"
  log "auth: ${#HDRS[@]} header(s) carregado(s) (valores não são logados)"
}

# ── Helpers exportados para xargs -P ─────────────────────────────────────────
dl_js() {
  local url="$1" h dest code
  h="$(printf '%s' "$url" | md5sum | cut -d' ' -f1)"
  dest="$JS_DIR/${h}.js"
  [[ -s "$dest" ]] && return 0
  code="$(curl -sk --max-time 30 -K "$AUTH_RC" -o "$dest" -w '%{http_code}' "$url" 2>/dev/null || echo 000)"
  case "$code" in
    2*) printf '%s\t%s\n' "$h" "$url" >> "$JS_MANIFEST" ;;
    *)  rm -f "$dest" ;;
  esac
}

js_base_url() {
  local f="$1" h u
  h="$(basename "$f" .js)"
  u="$(awk -F'\t' -v k="$h" '$1==k{print $2; exit}' "$JS_MANIFEST" 2>/dev/null || true)"
  printf '%s' "${u:-https://$DOMAIN/}"
}

js_urls() {
  local f="$1" base
  base="$(js_base_url "$f")"
  jsluice urls -R "$base" -u "$f" 2>/dev/null || true
}

js_map_sources() {
  local f="$1" base u dest
  [[ "$f" == *.map.js ]] && return 0
  base="$(grep -oE 'sourceMappingURL=[^[:space:]*"]+' "$f" 2>/dev/null | tail -n1 | cut -d= -f2- || true)"
  [[ -n "$base" ]] || return 0
  case "$base" in
    http*) u="$base" ;;
    /*)    u="https://${DOMAIN}${base}" ;;
    *)     u="$(js_base_url "$f")"; u="${u%/*}/${base}" ;;
  esac
  dest="${f}.map.js"
  curl -sk --max-time 20 -K "$AUTH_RC" -o "$dest" "$u" 2>/dev/null || true
  # sourcemap válido é JSON; descarta HTML de erro
  if [[ -s "$dest" ]] && [[ "$(head -c 1 "$dest")" != "{" ]]; then rm -f "$dest"; fi
}

arjun_one() {
  local url="$1" safe
  safe="$(printf '%s' "$url" | sed -E 's#^https?://##; s#[^A-Za-z0-9._-]#_#g' | cut -c1-100)"
  local extra=()
  [[ -n "${HDR_BLOB:-}" ]] && extra=(--headers "$HDR_BLOB")
  arjun -u "$url" --stable -t 5 -T 10 -q --rate-limit 30 "${extra[@]+"${extra[@]}"}" \
        -oT "$ARJUN_DIR/${safe}.txt" 2>/dev/null || true
}

export -f dl_js js_base_url js_urls js_map_sources arjun_one

# ── Credenciais opcionais (GitHub / Chaos) ───────────────────────────────────
GH_ENABLED=1
CHAOS_ENABLED=1
GH_TOKEN_CACHE=""
CHAOS_KEY_CACHE=""

github_token_value() {
  local t="${GITHUB_TOKEN:-}"
  if [[ -z "$t" && -s "$GH_TOKEN_FILE" ]]; then
    t="$(head -n1 "$GH_TOKEN_FILE" 2>/dev/null | tr -d '\r\n ')"
  fi
  printf '%s' "$t"
}

# Prioridade: CHAOS_KEY (env) → targets/chaos_key → ~/.config/chaos/config.yaml
chaos_key_value() {
  local k="${CHAOS_KEY:-}"
  if [[ -z "$k" && -s "$CHAOS_KEY_FILE" ]]; then
    k="$(head -n1 "$CHAOS_KEY_FILE" 2>/dev/null | tr -d '\r\n ')"
  fi
  if [[ -z "$k" && -r "$HOME/.config/chaos/config.yaml" ]]; then
    k="$(awk -F': *' '/^[[:space:]]*api-key:/{gsub(/"/,"",$2); gsub(/\047/,"",$2); print $2; exit}' \
          "$HOME/.config/chaos/config.yaml" 2>/dev/null | tr -d '[:space:]')"
  fi
  printf '%s' "$k"
}

# GitHub: 200 = ok | none = sem token | outro = HTTP de falha
gh_check() {
  local t; t="$(github_token_value)"
  [[ -n "$t" ]] || { printf 'none'; return 0; }
  mkdir -p /tmp/opencode 2>/dev/null
  local f; f="$(mktemp /tmp/opencode/ghhdr-XXXXXX 2>/dev/null)" || { printf 'none'; return 0; }
  printf 'Authorization: Bearer %s\nAccept: application/vnd.github+json\nUser-Agent: recon-high-end\n' "$t" > "$f"
  local c; c="$(curl -s -m 12 -o /dev/null -w '%{http_code}' -H @"$f" https://api.github.com/user 2>/dev/null || echo 000)"
  rm -f "$f"
  printf '%s' "$c"
}

# Valida de verdade: consulta um domínio neutro e exige 200 + subdomínios.
# Retorno: ok:<n> | none | fail:<http>
chaos_check() {
  local k; k="$(chaos_key_value)"
  [[ -n "$k" ]] || { printf 'none'; return 0; }
  mkdir -p /tmp/opencode 2>/dev/null
  local f body c n
  f="$(mktemp /tmp/opencode/chhdr-XXXXXX 2>/dev/null)" || { printf 'none'; return 0; }
  body="$(mktemp /tmp/opencode/chbody-XXXXXX 2>/dev/null)"
  printf 'Authorization: %s\n' "$k" > "$f"
  c="$(curl -s -m 15 -o "$body" -w '%{http_code}' -H @"$f" \
        https://dns.projectdiscovery.io/dns/projectdiscovery.io 2>/dev/null || echo 000)"
  n=0
  [[ -s "$body" ]] && n="$(jq -r '(.subdomains // []) | length' "$body" 2>/dev/null || echo 0)"
  rm -f "$f" "$body"
  if [[ "$c" == "200" ]] && [[ "$n" =~ ^[0-9]+$ ]] && (( n > 0 )); then
    printf 'ok:%s' "$n"
  else
    printf 'fail:%s' "$c"
  fi
  return 0
}

# Valida credenciais antes de usar. Cacheia por valor: se você trocar a key
# no meio do lote, a próxima checagem pega a nova.
preflight_credentials() {
  local t k c
  t="$(github_token_value)"
  if [[ "$t" != "$GH_TOKEN_CACHE" ]]; then
    GH_TOKEN_CACHE="$t"
    if [[ -z "$t" ]]; then
      GH_ENABLED=0; warn "github-subdomains: sem token — pulando fonte"
    else
      c="$(gh_check)"
      if [[ "$c" == "200" ]]; then
        GH_ENABLED=1
      else
        GH_ENABLED=0; warn "github-subdomains: token inválido (HTTP ${c}) — pulando fonte"
      fi
    fi
  fi

  k="$(chaos_key_value)"
  if (( SKIP_CHAOS )); then
    CHAOS_ENABLED=0
    CHAOS_KEY_CACHE=""   # religar o toggle força revalidação
  elif [[ "$k" != "$CHAOS_KEY_CACHE" ]]; then
    CHAOS_KEY_CACHE="$k"
    c="$(chaos_check)"
    case "$c" in
      ok:*) CHAOS_ENABLED=1; log "chaos: key válida (${c#ok:} subdomínios no teste)" ;;
      none) CHAOS_ENABLED=0; warn "chaos: sem key (${CHAOS_KEY_FILE} / CHAOS_KEY / config) — pulando fonte" ;;
      *)    CHAOS_ENABLED=0; warn "chaos: key inválida ou API sem resposta (HTTP ${c#fail:}) — pulando fonte" ;;
    esac
  fi

  (( GH_ENABLED && CHAOS_ENABLED )) && log "credenciais: github ok, chaos habilitado"
  return 0
}

check_keys() {
  local gc cc k
  gc="$(gh_check)"
  cc="$(chaos_check)"
  k="$(chaos_key_value)"
  if [[ "$gc" == "200" ]]; then
    printf 'github-subdomains : OK (%s)\n' "$GH_TOKEN_FILE"
  elif [[ "$gc" == "none" ]]; then
    printf 'github-subdomains : AUSENTE (crie %s ou export GITHUB_TOKEN)\n' "$GH_TOKEN_FILE"
  else
    printf 'github-subdomains : FALHA (HTTP %s) — token inválido/expirado\n' "$gc"
  fi
  if [[ "$cc" == "none" ]]; then
    printf 'chaos             : AUSENTE (crie %s ou export CHAOS_KEY)\n' "$CHAOS_KEY_FILE"
  elif [[ "$cc" == ok:* ]]; then
    printf 'chaos             : OK (%s subdomínios no domínio de teste)\n' "${cc#ok:}"
  else
    printf 'chaos             : FALHA (HTTP %s) — key inválida/expirada\n' "${cc#fail:}"
  fi
  return 0
}


# =============================================================================
#  FASE 1 — ASSET DISCOVERY
# =============================================================================
phase_asset() {
  local passive="$OUT/passive_raw.txt"
  : > "$passive"
  local d="$DOMAIN"

  preflight_credentials

  # Chaos primeiro: dataset em massa, rápido, e já mostra progresso
  if have chaos && (( CHAOS_ENABLED )); then
    local k cb ca
    k="$(chaos_key_value)"
    cb="$(count "$passive")"
    # key via env: não aparece no argv do processo
    timeout 180 env PDCP_API_KEY="$k" chaos -d "$d" -silent -duc 2>>"$LOG" >> "$passive" \
      || warn "chaos falhou"
    ca="$(count "$passive")"
    if (( ca == cb )); then
      warn "chaos: 0 resultados para ${d}"
    else
      log "chaos: $((ca - cb)) nome(s) adicionado(s) [total $(count "$passive")]"
    fi
  fi

  # crt.sh — valida JSON antes de parsear (rate limit devolve HTML)
  local crt="" attempt
  for attempt in 1 2; do
    crt="$(timeout 120 curl -s "https://crt.sh/?q=%25.${d}&output=json" 2>>"$LOG" || true)"
    if [[ -n "$crt" ]] && printf '%s' "$crt" | jq -e . >/dev/null 2>/dev/null; then
      break
    fi
    crt=""
    sleep 2
  done
  if [[ -n "$crt" ]]; then
    printf '%s' "$crt" | jq -r '.[].name_value? // empty' 2>>"$LOG" >> "$passive" || true
    log "crt.sh: total $(count "$passive") nome(s)"
  else
    warn "crt.sh: resposta inválida/vazia (rate limit?) — pulando"
  fi

  if have github-subdomains && (( GH_ENABLED )); then
    local ghtoken gh_before gh_after
    ghtoken="$(github_token_value)"
    if [[ -n "$ghtoken" ]]; then
      gh_before="$(count "$passive")"
      log "github-subdomains: consultando (pode levar alguns minutos)"
      # token via env: não aparece no argv do processo
      GITHUB_TOKEN="$ghtoken" timeout 300 github-subdomains -d "$d" 2>>"$LOG" >> "$passive" \
        || warn "github-subdomains falhou (token escopos/rate limit?)"
      gh_after="$(count "$passive")"
      log "github-subdomains: $((gh_after - gh_before)) nome(s) adicionado(s) [total ${gh_after}]"
    else
      log "github-subdomains: sem token — pulando"
    fi
  fi

  # subfinder por último: é a fonte mais lenta, com teto de tempo
  if have subfinder; then
    local sflags=(-silent -duc -timeout "$SUBFINDER_TIMEOUT" -max-time "$SUBFINDER_MAX_TIME")
    (( SUBFINDER_ALL )) && sflags+=(-all)
    (( SUBFINDER_RECURSIVE )) && sflags+=(-recursive)
    timeout 600 subfinder -d "$d" "${sflags[@]}" 2>>"$LOG" >> "$passive" \
      || warn "subfinder falhou (timeout/erro)"
    log "subfinder: total $(count "$passive") nome(s) (max-time ${SUBFINDER_MAX_TIME}m)"
  else
    warn "subfinder ausente"
  fi

  # Normaliza: lowercase, remove wildcard/ponto inicial, mantém só o domínio alvo
  awk -v dom="$d" '
    { gsub(/\r/,""); gsub(/^\*\./,""); gsub(/^\./,""); gsub(/\.$/,"");
      if (length($0)) print tolower($0) }
  ' "$passive" 2>/dev/null \
    | grep -E "(^|\.)${d//./\\.}$" | sort -u > "$OUT/passive.txt" || true

  # Bruteforce DNS (ShuffleDNS)
  : > "$OUT/brute.txt"
  if (( ! SKIP_BRUTE )) && have shuffledns && [[ -s "$DNS_WORDLIST" && -s "$RESOLVERS" ]]; then
    log "bruteforce DNS: $(basename "$DNS_WORDLIST")"
    timeout 2400 shuffledns -d "$d" -w "$DNS_WORDLIST" -r "$RESOLVERS" \
      -mode bruteforce -silent 2>>"$LOG" > "$OUT/brute.txt" || warn "shuffledns falhou"
  elif (( SKIP_BRUTE )); then
    log "bruteforce: pulado (--skip-brute)"
  else
    warn "bruteforce: wordlist/resolvers ausentes, pulando"
  fi

  cat "$OUT/passive.txt" "$OUT/brute.txt" 2>/dev/null | sort -u > "$OUT/subdomains_candidates.txt" || true

  # Permutações (alterx) → resolve (dnsx)
  # Sem 'head' no meio da pipeline: head fecha o stream e o sort morre com
  # SIGPIPE (pipefail acusava falha falsa). O teto é aplicado com awk.
  : > "$OUT/permutations.txt"
  if have alterx && have dnsx; then
    local perm_in="$OUT/.perm_input.txt" perm_out="$OUT/.perm_out.txt"
    head -n "$PERM_INPUT" "$OUT/subdomains_candidates.txt" > "$perm_in" 2>/dev/null || true
    if ! timeout 600 alterx -silent < "$perm_in" > "$perm_out" 2>>"$LOG"; then
      warn "alterx retornou erro (saída preservada)"
    fi
    if [[ -s "$perm_out" ]]; then
      sort -u "$perm_out" | awk -v n="$MAX_PERMUTATIONS" 'NR <= n' \
        | timeout 900 dnsx -silent -t 100 -r "$RESOLVERS" 2>>"$LOG" \
        | sort -u > "$OUT/permutations.txt" || \
        warn "dnsx retornou erro (permutações parciais: $(count "$OUT/permutations.txt"))"
    else
      warn "alterx não gerou permutações"
    fi
    rm -f "$perm_in" "$perm_out"
  else
    warn "alterx/dnsx ausentes: sem permutações"
  fi

  # Resolve tudo que é conhecido (fonte de verdade para portas/HTTP)
  local subs_tmp="$OUT/.subs_resolved.txt"
  if ! sort -u "$OUT/subdomains_candidates.txt" "$OUT/permutations.txt" 2>/dev/null \
      | timeout 900 dnsx -silent -t 100 -r "$RESOLVERS" 2>>"$LOG" \
      | sort -u > "$subs_tmp"; then
    warn "resolução final retornou erro (usando saída parcial)"
  fi
  if [[ -s "$subs_tmp" ]]; then
    mv -f "$subs_tmp" "$OUT/subdomains.txt"
  else
    warn "dnsx não resolveu nada — mantendo candidatos sem resolução"
    cp -f "$OUT/subdomains_candidates.txt" "$OUT/subdomains.txt"
  fi

  log "asset: $(count "$OUT/subdomains.txt") hosts resolvidos (passivo $(count "$OUT/passive.txt"), brute $(count "$OUT/brute.txt"), perm $(count "$OUT/permutations.txt"))"
  db_log asset subfinder ok "$OUT/subdomains.txt" "hosts=$(count "$OUT/subdomains.txt")" 0
  stamp "$OUT/subdomains.txt" subdomains
  stamp "$OUT/passive.txt" subfinder
}

# Deriva listas do JSONL do httpx: normaliza :80/:443 e separa ruído de CDN
derive_live_lists() {
  local src="$OUT/live.jsonl"
  if [[ -s "$src" ]]; then
    jq -r 'select(.url != null) | .url
      | if startswith("https://") then sub(":443$";"")
        elif startswith("http://") then sub(":80$";"") else . end' \
      "$src" 2>/dev/null | sort -u > "$OUT/live.txt" || true
    # remove 400 "plain HTTP request sent to HTTPS port" de CDN/WAF
    jq -r 'select(.url != null and ((.status_code == 400 and (.cdn // false)) | not)) | .url
      | if startswith("https://") then sub(":443$";"")
        elif startswith("http://") then sub(":80$";"") else . end' \
      "$src" 2>/dev/null | sort -u > "$OUT/live_clean.txt" || true
  else
    : > "$OUT/live.txt"
    : > "$OUT/live_clean.txt"
  fi
  awk '{print $1}' "$OUT/live.txt" 2>/dev/null \
    | sed -E 's#^[a-z]+://##; s#[:/].*$##' | awk 'NF' | sort -u > "$OUT/live_hosts.txt" || true
}

# Prioriza alvos para o crawl: fora de CDN, status útil, nome "de aplicação".
build_crawl_targets() {
  local cap="${KATANA_MAX_HOSTS:-0}"
  jq -r 'select(.url != null)
    | (.url | if startswith("https://") then sub(":443$";"") elif startswith("http://") then sub(":80$";"") else . end) as $u
    | [ (if (.cdn // false) then 0 else 1 end),
        (if .status_code == 200 then 2 elif (.status_code == 401 or .status_code == 403) then 1 else 0 end),
        (if ($u | test("api|app|admin|auth|account|checkout|pay|graphql|portal|dashboard|internal|staging|hml|homolog|dev|sandbox|beta|gateway|bff|backend|mcp|profile"; "i")) then 3 else 0 end),
        $u ] | @tsv' "$OUT/live.jsonl" 2>/dev/null \
    | awk -F'\t' '{printf "%d\t%s\n", $1+$2+$3, $4}' \
    | sort -t$'\t' -k1,1nr -k2,2 \
    | cut -f2 \
    | awk '!seen[$0]++' \
    | grep -Eiv "^https?://(${CRAWL_EXCLUDE})\." \
    > "$OUT/crawl_targets_all.txt" 2>/dev/null || true

  if (( cap > 0 )); then
    head -n "$cap" "$OUT/crawl_targets_all.txt" > "$OUT/crawl_targets.txt" 2>/dev/null || true
  else
    cp -f "$OUT/crawl_targets_all.txt" "$OUT/crawl_targets.txt" 2>/dev/null || true
  fi
  log "crawl: $(count "$OUT/crawl_targets.txt") alvos priorizados de $(count "$OUT/crawl_targets_all.txt") (cap=${cap:-todos})"
}

phase_ports_http() {
  : > "$OUT/probe_targets.txt"

  if (( SKIP_PORTS )) || [[ "$PORTS_MODE" == "none" ]]; then
    log "portas: pulado (mode=${PORTS_MODE})"
    : > "$OUT/open_ports.txt"
  elif have naabu; then
    local tp=100
    [[ "$PORTS_MODE" == "full" ]] && tp="$NAABU_TOP_PORTS"
    log "portas: top-${tp} (mode=${PORTS_MODE}, -ec, excl ${NAABU_EXCLUDE})"
    timeout 1200 naabu -list "$OUT/subdomains.txt" -top-ports "$tp" \
      -ep "$NAABU_EXCLUDE" -ec -silent -rate 2000 2>>"$LOG" \
      | sort -u > "$OUT/open_ports.txt" || warn "naabu falhou"
  else
    warn "naabu ausente"
  fi

  # host:80/host:443 são redundantes: o hostname já é sondado nos dois esquemas
  cat "$OUT/open_ports.txt" "$OUT/subdomains.txt" 2>/dev/null \
    | sed -E 's/:(80|443)$//' \
    | awk 'NF' | sort -u > "$OUT/probe_targets.txt" || true

  : > "$OUT/live.jsonl"
  local bin=""
  if have httpx-toolkit; then bin="httpx-toolkit"; elif have httpx; then bin="httpx"; fi
  if [[ -n "$bin" ]]; then
    log "probe HTTP via ${bin} em $(count "$OUT/probe_targets.txt") alvos (saída em live.jsonl)"
    # stdout em /dev/null: -o já grava, evita despejar milhares de JSON no terminal
    "$bin" -l "$OUT/probe_targets.txt" \
      -silent -json -title -sc -cl -td -server -location -fr -fc 404 \
      -timeout "$HTTP_TIMEOUT" -retries 1 -threads 50 -rl 150 \
      "${HDR_FLAGS[@]+"${HDR_FLAGS[@]}"}" \
      -o "$OUT/live.jsonl" 2>>"$LOG" >/dev/null || warn "httpx falhou parcialmente"
  else
    warn "httpx/httpx-toolkit ausentes: sem probe HTTP"
  fi

  derive_live_lists

  # TLS: SANs/CNs revelam assets fora do inventário esperado
  : > "$OUT/tls_assets.txt"
  if have tlsx && [[ -s "$OUT/live_hosts.txt" ]]; then
    timeout 900 tlsx -l "$OUT/live_hosts.txt" -san -cn -json -silent -timeout 8 2>>"$LOG" \
      | jq -r '(.subject_cn // empty), (.subject_an[]? // empty), (.host // empty)' 2>/dev/null \
      | tr -d '"' | tr ',' '\n' | awk 'NF' | sort -u \
      | grep -E "(^|\.)${DOMAIN//./\\.}$" \
      | awk 'NR==FNR{seen[$0];next} !($0 in seen)' "$OUT/subdomains.txt" - \
      > "$OUT/tls_assets.txt" 2>/dev/null || true
  fi

  # Assets descobertos só no certificado entram no inventário e são sondados
  if [[ -s "$OUT/tls_assets.txt" ]]; then
    sort -u "$OUT/subdomains.txt" "$OUT/tls_assets.txt" > "$OUT/.subs.tmp" 2>/dev/null \
      && mv -f "$OUT/.subs.tmp" "$OUT/subdomains.txt"
    if [[ -n "$bin" ]]; then
      log "probe HTTP nos assets TLS novos ($(count "$OUT/tls_assets.txt"))"
      "$bin" -l "$OUT/tls_assets.txt" \
        -silent -json -title -sc -cl -td -server -location -fr -fc 404 \
        -timeout "$HTTP_TIMEOUT" -retries 1 -threads 25 -rl 100 \
        "${HDR_FLAGS[@]+"${HDR_FLAGS[@]}"}" \
        -o "$OUT/live_tls.jsonl" 2>>"$LOG" >/dev/null || warn "httpx (TLS) parcial"
      cat "$OUT/live_tls.jsonl" >> "$OUT/live.jsonl" 2>/dev/null || true
      derive_live_lists
    fi
  fi

  build_crawl_targets

  log "http: $(count "$OUT/live.txt") URLs ($(count "$OUT/live_clean.txt") sem ruído de CDN) | portas: $(count "$OUT/open_ports.txt") | TLS novos: $(count "$OUT/tls_assets.txt")"
  db_log http httpx ok "$OUT/live.txt" \
    "live=$(count "$OUT/live.txt") clean=$(count "$OUT/live_clean.txt") ports=$(count "$OUT/open_ports.txt")" 0
  stamp "$OUT/live.txt" httpx
  stamp "$OUT/live_clean.txt" httpx-clean
  stamp "$OUT/open_ports.txt" naabu
  stamp "$OUT/tls_assets.txt" tlsx
}

# =============================================================================
#  FASE 2 — CONTENT DISCOVERY
# =============================================================================
phase_content() {
  local t0=$SECONDS
  : > "$OUT/urls_katana.txt"; : > "$OUT/urls_wayback.txt"; : > "$OUT/urls_gau.txt"

  # ── Histórico primeiro (barato e cobre tudo de uma vez) ──────────────────
  if (( SKIP_HISTORY )); then
    log "histórico: pulado (--skip-history)"
  elif ! have waybackurls && ! have gau; then
    warn "waybackurls/gau ausentes"
  else
    if (( HISTORY_PER_HOST )) && [[ -s "$OUT/live_hosts.txt" ]]; then
      log "histórico: modo por host (${THREADS} paralelos) — lento"
      if have waybackurls; then
        xargs -r -P "$THREADS" -I{} bash -c 'timeout 300 waybackurls "$1" 2>/dev/null' _ {} \
          < "$OUT/live_hosts.txt" > "$OUT/urls_wayback.txt" || warn "waybackurls parcial"
      fi
      if have gau; then
        xargs -r -P "$THREADS" -I{} bash -c \
          'timeout 300 gau --threads 2 --blacklist png,jpg,jpeg,gif,svg,ico,woff,woff2,ttf,css,mp4,webp "$1" 2>/dev/null' _ {} \
          < "$OUT/live_hosts.txt" > "$OUT/urls_gau.txt" || warn "gau parcial"
      fi
    else
      # 1 consulta por domínio: cobre subdomínios de uma vez (segundos/minutos)
      local wb_code
      wb_code="$(curl -s -o /dev/null -m 8 -w '%{http_code}' https://web.archive.org/ 2>/dev/null || echo 000)"
      if have waybackurls && [[ "$wb_code" =~ ^[23] ]]; then
        log "waybackurls: domínio ${DOMAIN} (subs incluídos)"
        timeout 900 waybackurls "$DOMAIN" > "$OUT/urls_wayback.txt" 2>>"$LOG" \
          || warn "waybackurls parcial"
        log "wayback: $(count "$OUT/urls_wayback.txt") URLs"
      elif have waybackurls; then
        warn "waybackurls: web.archive.org inacessível (HTTP ${wb_code}) — pulando"
      fi
      if have gau; then
        log "gau: domínio ${DOMAIN} (--subs, providers ${GAU_PROVIDERS})"
        timeout 1200 gau --subs --providers "$GAU_PROVIDERS" --timeout 30 --threads 5 \
          --blacklist png,jpg,jpeg,gif,svg,ico,woff,woff2,ttf,css,mp4,webp \
          "$DOMAIN" > "$OUT/urls_gau.txt" 2>>"$LOG" || warn "gau parcial"
        log "gau: $(count "$OUT/urls_gau.txt") URLs"
      fi
    fi
  fi

  # ── katana em chunks (memória controlada) ────────────────────────────────
  local crawl_list="$OUT/crawl_targets.txt"
  [[ -s "$crawl_list" ]] || crawl_list="$OUT/live_clean.txt"
  [[ -s "$crawl_list" ]] || crawl_list="$OUT/live.txt"

  if have katana && [[ -s "$crawl_list" ]]; then
    local extra=() chunk_dir="$OUT/.katana_chunks" f i=0 rc
    (( KATANA_HEADLESS )) && extra+=(-hl -nos)
    (( KATANA_AFF )) && extra+=(-aff)
    (( KATANA_JSLUICE )) && extra+=(-jsl)
    (( KATANA_FSU )) && extra+=(-fsu)

    rm -rf "$chunk_dir"; mkdir -p "$chunk_dir"
    split -l "$KATANA_CHUNK" "$crawl_list" "$chunk_dir/part_" 2>/dev/null || true
    local total_chunks
    total_chunks="$(find "$chunk_dir" -name 'part_*' | wc -l | tr -d ' ')"
    log "katana: $(count "$crawl_list") alvos em ${total_chunks} chunk(s) de ${KATANA_CHUNK} (depth ${KATANA_DEPTH}, jsl=$([[ $KATANA_JSLUICE -eq 1 ]] && echo on || echo off), aff=$([[ $KATANA_AFF -eq 1 ]] && echo on || echo off))"

    for f in "$chunk_dir"/part_*; do
      [[ -s "$f" ]] || continue
      i=$((i + 1))
      rc=0
      # memória baixa = não insiste (evita OOM em cascata)
      local mem_avail
      mem_avail="$(awk '/^MemAvailable:/{printf "%d", $2/1024}' /proc/meminfo 2>/dev/null || true)"
      [[ "$mem_avail" =~ ^[0-9]+$ ]] || mem_avail=9999
      if (( mem_avail < 1200 )); then
        warn "katana: memória livre ${mem_avail}MB — pulando chunk ${i}/${total_chunks}"
        continue
      fi
      timeout "$KATANA_CHUNK_TIMEOUT" katana -list "$f" \
        -d "$KATANA_DEPTH" -jc -xhr -kf all -fs "$KATANA_FS" \
        -rl 120 -c 5 -timeout "$HTTP_TIMEOUT" -silent -duc \
        "${extra[@]+"${extra[@]}"}" "${HDR_FLAGS[@]+"${HDR_FLAGS[@]}"}" \
        2>>"$LOG" | head -n "$KATANA_MAX_URLS_PER_CHUNK" >> "$OUT/urls_katana.txt"
      rc=${PIPESTATUS[0]}
      if (( rc == 137 )); then
        warn "katana: chunk ${i}/${total_chunks} morto por OOM — seguindo"
      elif (( rc == 141 )); then
        log "katana: chunk ${i}/${total_chunks} atingiu o teto de ${KATANA_MAX_URLS_PER_CHUNK} URLs"
      elif (( rc != 0 && rc != 124 )); then
        warn "katana: chunk ${i}/${total_chunks} rc=${rc}"
      fi
      log "katana: chunk ${i}/${total_chunks} (acumulado $(count "$OUT/urls_katana.txt") URLs)"
    done
    rm -rf "$chunk_dir"
  else
    warn "katana ausente ou sem alvos para crawl"
  fi

  # ── Merge + dedup inteligente ────────────────────────────────────────────
  cat "$OUT/urls_katana.txt" "$OUT/urls_wayback.txt" "$OUT/urls_gau.txt" 2>/dev/null \
    | grep -E '^https?://' | sed -E 's/#.*$//' | awk 'NF' | sort -u > "$OUT/endpoints_crawl_raw.txt" || true

  if have uro && [[ -s "$OUT/endpoints_crawl_raw.txt" ]]; then
    uro -i "$OUT/endpoints_crawl_raw.txt" -o "$OUT/endpoints_crawl.txt" 2>>"$LOG" \
      || cp -f "$OUT/endpoints_crawl_raw.txt" "$OUT/endpoints_crawl.txt"
  else
    cp -f "$OUT/endpoints_crawl_raw.txt" "$OUT/endpoints_crawl.txt" 2>/dev/null || : > "$OUT/endpoints_crawl.txt"
  fi

  log "content: $(count "$OUT/endpoints_crawl.txt") endpoints em $((SECONDS - t0))s (katana $(count "$OUT/urls_katana.txt") / wayback $(count "$OUT/urls_wayback.txt") / gau $(count "$OUT/urls_gau.txt"))"
  db_log content katana ok "$OUT/endpoints_crawl.txt" \
    "endpoints=$(count "$OUT/endpoints_crawl.txt") auth=$([[ ${#HDRS[@]} -gt 0 ]] && echo yes || echo no)" 0
  stamp "$OUT/endpoints_crawl.txt" katana
  stamp "$OUT/urls_wayback.txt" waybackurls
  stamp "$OUT/urls_gau.txt" gau
}

# =============================================================================
#  FASE 3 — JS ANALYSIS (jsluice + trufflehog)
# =============================================================================
phase_js() {
  mkdir -p "$JS_DIR"
  : > "$JS_MANIFEST"

  cat "$OUT/endpoints_crawl.txt" 2>/dev/null \
    | grep -Ei '\.(m?js)(\?|$)' | sort -u | head -n "$MAX_JS" > "$OUT/js_files.txt" || true

  log "js: baixando $(count "$OUT/js_files.txt") arquivos (P=${THREADS})"
  if [[ -s "$OUT/js_files.txt" ]]; then
    xargs -r -P "$THREADS" -I{} bash -c 'dl_js "$1"' _ {} < "$OUT/js_files.txt" \
      || warn "download JS parcial"
  fi
  local downloaded
  downloaded="$(find "$JS_DIR" -maxdepth 1 -type f -name '*.js' 2>/dev/null | wc -l | tr -d ' ')"
  log "js: ${downloaded} arquivo(s) baixado(s)"

  # Sourcemaps → código original + rotas
  if (( downloaded > 0 )); then
    find "$JS_DIR" -maxdepth 1 -type f -name '*.js' -print0 2>/dev/null \
      | xargs -0 -r -P "$THREADS" -I{} bash -c 'js_map_sources "$1"' _ {} || warn "sourcemaps parcial"
  fi

  : > "$OUT/js_endpoints.jsonl"
  if (( downloaded > 0 )); then
    find "$JS_DIR" -maxdepth 1 -type f -name '*.js' -print0 2>/dev/null \
      | xargs -0 -r -P "$THREADS" -I{} bash -c 'js_urls "$1"' _ {} \
      >> "$OUT/js_endpoints.jsonl" 2>>"$LOG" || warn "jsluice parcial"
  fi

  jq -r 'select(.url != null) | .url' "$OUT/js_endpoints.jsonl" 2>/dev/null \
    | awk 'NF && $0 != "EXPR"' | sort -u > "$OUT/js_endpoints.txt" || : > "$OUT/js_endpoints.txt"

  # Rotas originais dos sourcemaps
  if (( downloaded > 0 )); then
    find "$JS_DIR" -maxdepth 1 -type f -name '*.map.js' -print0 2>/dev/null \
      | xargs -0 -r -P "$THREADS" -I{} bash -c 'jq -r ".sources[]? // empty" "$1" 2>/dev/null' _ {} \
      | awk 'NF' | sed "s#^webpack://##; s#^\./##" | sed "s#^#https://${DOMAIN}/#" \
      | sort -u >> "$OUT/js_endpoints.txt" || true
  fi
  sort -u -o "$OUT/js_endpoints.txt" "$OUT/js_endpoints.txt" 2>/dev/null || true

  # Segredos: jsluice (rápido) + trufflehog (profundo)
  : > "$OUT/js_secrets.jsonl"
  if (( downloaded > 0 )); then
    find "$JS_DIR" -maxdepth 1 -type f -name '*.js' -print0 2>/dev/null \
      | xargs -0 -r jsluice secrets -c "$THREADS" >> "$OUT/js_secrets.jsonl" 2>>"$LOG" || true

    if have trufflehog; then
      timeout 1200 trufflehog filesystem "$JS_DIR" --no-verification --json --no-update \
        --concurrency 10 >> "$OUT/js_secrets.jsonl" 2>>"$LOG" || warn "trufflehog parcial"
    fi

    jq -r '
      if .kind then "jsluice\t\(.kind)\t\(.data | tostring | .[0:80])\t\(.filename // "")"
      elif .DetectorName then "trufflehog\t\(.DetectorName)\t\(.Raw // "" | .[0:80])\t\(.SourceMetadata.Data.Filesystem.file // "")"
      else empty end' "$OUT/js_secrets.jsonl" 2>/dev/null \
      | sort -u > "$OUT/js_secrets.txt" || true
  fi

  # União final de endpoints (crawl + JS)
  cat "$OUT/endpoints_crawl.txt" "$OUT/js_endpoints.txt" 2>/dev/null \
    | grep -E '^https?://' | awk 'NF' | sort -u > "$OUT/endpoints_all_raw.txt" || true
  if have uro && [[ -s "$OUT/endpoints_all_raw.txt" ]]; then
    uro -i "$OUT/endpoints_all_raw.txt" -o "$OUT/endpoints.txt" 2>>"$LOG" \
      || cp -f "$OUT/endpoints_all_raw.txt" "$OUT/endpoints.txt"
  else
    cp -f "$OUT/endpoints_all_raw.txt" "$OUT/endpoints.txt" 2>/dev/null || : > "$OUT/endpoints.txt"
  fi

  log "js: $(count "$OUT/js_endpoints.txt") rotas extraídas | $(count "$OUT/js_secrets.txt") segredos | endpoints totais: $(count "$OUT/endpoints.txt")"
  db_log js jsluice ok "$OUT/js_endpoints.txt" \
    "js_files=${downloaded} routes=$(count "$OUT/js_endpoints.txt") secrets=$(count "$OUT/js_secrets.txt")" 0
  stamp "$OUT/js_files.txt" js-files
  stamp "$OUT/js_endpoints.txt" jsluice
  stamp "$OUT/js_secrets.txt" secrets
  stamp "$OUT/endpoints.txt" endpoints
}

# =============================================================================
#  FASE 4 — PARAMETER DISCOVERY
# =============================================================================
classify_params() {
  local cls="$1" out="$2" regex="$3" src="$4"
  : > "$out"
  [[ -s "$src" ]] || return 0
  if have gf && gf -list 2>/dev/null | grep -qx "$cls"; then
    gf "$cls" < "$src" 2>/dev/null | sort -u > "$out" || true
  else
    # Fallback: gf patterns custom podem não existir nesta instalação
    grep -Ei "$regex" "$src" 2>/dev/null | sort -u > "$out" || true
  fi
}

phase_params() {
  mkdir -p "$ARJUN_DIR"
  local src="$OUT/endpoints.txt"
  [[ -s "$src" ]] || { warn "params: sem endpoints"; return 0; }

  classify_params xss      "$OUT/params_xss.txt"      '[?&](q|s|search|query|keyword|name|message|comment|title|content|text|lang|page|view|template|html|user|email|callback)=' "$src"
  classify_params sqli     "$OUT/params_sqli.txt"     '[?&](id|pid|cat|category|select|where|order|sort|by|limit|offset|num|item|product|report|filter|group)=' "$src"
  classify_params ssrf     "$OUT/params_ssrf.txt"     '[?&](url|uri|link|src|dest|destination|redirect|return|next|path|target|proxy|fetch|load|file|host|domain|callback|webhook|image|avatar|icon|feed|api|site|resource|endpoint)=' "$src"
  classify_params redirect "$OUT/params_redirect.txt" '[?&](url|uri|redirect|redirect_uri|return|return_to|returnto|return_url|next|dest|destination|continue|target|r|u|go|out|view|callback|back)=' "$src"
  classify_params idor     "$OUT/params_idor.txt"     '[?&](id|uid|user|user_id|account|account_id|profile|pid|order|order_id|invoice|doc|document|file|file_id|report|record|ref|number|no|key|token|hash)=' "$src"

  cat "$OUT/params_xss.txt" "$OUT/params_sqli.txt" "$OUT/params_ssrf.txt" \
      "$OUT/params_redirect.txt" "$OUT/params_idor.txt" 2>/dev/null \
    | sort -u > "$OUT/params_all.txt" || true

  : > "$OUT/arjun_params.txt"
  if (( SKIP_ARJUN )); then
    log "arjun: pulado (--skip-arjun)"
  elif have arjun; then
    # prioriza os alvos "de aplicação" (crawl_targets) em vez de pegar live.txt cru
    head -n "$MAX_ARJUN" "$OUT/crawl_targets.txt" > "$OUT/arjun_targets.txt" 2>/dev/null || true
    if [[ ! -s "$OUT/arjun_targets.txt" ]]; then
      awk '{print $1}' "$OUT/live.txt" 2>/dev/null \
        | grep -oE '^https?://[^/]+' | sort -u | head -n "$MAX_ARJUN" > "$OUT/arjun_targets.txt" || true
    fi
    log "arjun: $(count "$OUT/arjun_targets.txt") origins priorizados (P=5, parametros ocultos)"
    xargs -r -P 5 -I{} bash -c 'arjun_one "$1"' _ {} < "$OUT/arjun_targets.txt" 2>>"$LOG" || warn "arjun parcial"
    cat "$ARJUN_DIR"/*.txt 2>/dev/null | awk 'NF' | sort -u > "$OUT/arjun_params.txt" || true
  else
    warn "arjun ausente"
  fi

  log "params: xss=$(count "$OUT/params_xss.txt") sqli=$(count "$OUT/params_sqli.txt") ssrf=$(count "$OUT/params_ssrf.txt") redirect=$(count "$OUT/params_redirect.txt") idor=$(count "$OUT/params_idor.txt") arjun=$(count "$OUT/arjun_params.txt")"
  db_log params "gf+arjun" ok "$OUT/params_all.txt" "classified=$(count "$OUT/params_all.txt") arjun=$(count "$OUT/arjun_params.txt")" 0
  stamp "$OUT/params_all.txt" params
  stamp "$OUT/arjun_params.txt" arjun
}

# =============================================================================
#  FASE 5 — FILTRO DE DINHEIRO (business logic)
# =============================================================================
phase_high_value() {
  local src="$OUT/endpoints.txt"
  [[ -s "$src" ]] || { warn "high-value: sem endpoints"; return 0; }
  [[ -n "${HV_AWK:-}" ]] || HV_AWK="$(mktemp /tmp/opencode/hv-XXXXXX.awk 2>/dev/null || echo /tmp/opencode/hv.awk)"

  local kws="withdraw:12,transfer:12,payout:12,payment:10,checkout:10,wallet:10,redeem:10,admin:10,internal:10,apikey:10,api_key:10,kyc:10,bank:10,balance:8,invoice:8,billing:8,refund:8,transaction:8,coupon:8,subscription:8,order:8,profile:8,account:8,password:8,role:8,permission:8,graphql:8,webhook:8,oauth:8,jwt:8,iban:8,card:8,ssn:8,secret:8,credit:6,debit:6,manage:6,invite:6,api/v1:6,api/v2:6,api/v3:6,api/v4:6,user:6,reset:6,token:6,session:6,export:6,download:6,upload:6,import:6,delete:6,update:6,bulk:6,staff:6,sso:6,saml:6,mfa:6,2fa:6,verify:6,discount:6,plan:4,signup:4,register:4,callback:4"

  # Superfície de ataque mastigada: só endpoints com query e só rotas de API
  grep -E '\?' "$src" 2>/dev/null | sort -u > "$OUT/endpoints_params.txt" || true
  grep -Ei '/(api|rest|graphql|rpc|bff|internal|admin)(/|$)|/v[0-9]+/' "$src" 2>/dev/null \
    | sort -u > "$OUT/endpoints_api.txt" || true
  log "superfície: $(count "$OUT/endpoints_params.txt") endpoints com params | $(count "$OUT/endpoints_api.txt") rotas de API"

  cat > "$HV_AWK" <<'AWK'
BEGIN {
  n = split(ENVIRON["HV_KWS"], parts, ",")
  for (i = 1; i <= n; i++) { split(parts[i], kv, ":"); kw[i] = tolower(kv[1]); sc[i] = kv[2] + 0 }
}
{
  l = tolower($0); s = 0; hit = ""
  for (i = 1; i <= n; i++) {
    if (index(l, kw[i]) > 0) { s += sc[i]; hit = hit (hit == "" ? "" : ",") kw[i] }
  }
  if (s > 0) printf "%d\t%s\t%s\n", s, hit, $0
}
AWK

  HV_KWS="$kws" awk -f "$HV_AWK" "$src" 2>/dev/null \
    | sort -t$'\t' -k1,1nr -k3,3 \
    | awk -F'\t' '!seen[$3]++' > "$OUT/high_value_targets_scored.tsv" || true

  awk -F'\t' '{print $3}' "$OUT/high_value_targets_scored.tsv" 2>/dev/null \
    | head -n 500 > "$OUT/high_value_targets.txt" || : > "$OUT/high_value_targets.txt"

  grep -Ei 'pay|transfer|withdraw|payout|billing|invoice|refund|wallet|balance|credit|debit|transaction|coupon|redeem|checkout|subscription|order|cart|bank|card|iban' \
    "$OUT/high_value_targets.txt" 2>/dev/null | sort -u > "$OUT/hv_payments.txt" || : > "$OUT/hv_payments.txt"
  grep -Ei 'admin|internal|staff|manage|role|permission|superuser|console|backoffice|dashboard' \
    "$OUT/high_value_targets.txt" 2>/dev/null | sort -u > "$OUT/hv_admin.txt" || : > "$OUT/hv_admin.txt"
  grep -Ei '/api/|graphql|webhook|/v[0-9]+/|/rpc' \
    "$OUT/high_value_targets.txt" 2>/dev/null | sort -u > "$OUT/hv_api.txt" || : > "$OUT/hv_api.txt"
  grep -Ei 'login|logout|auth|token|session|password|reset|mfa|2fa|sso|oauth|saml|jwt|apikey|api_key|signup|register' \
    "$OUT/high_value_targets.txt" 2>/dev/null | sort -u > "$OUT/hv_auth.txt" || : > "$OUT/hv_auth.txt"
  grep -Ei 'export|download|upload|import|kyc|ssn|pii|profile|account|document|report' \
    "$OUT/high_value_targets.txt" 2>/dev/null | sort -u > "$OUT/hv_data.txt" || : > "$OUT/hv_data.txt"

  rm -f "$HV_AWK"
  log "high-value: $(count "$OUT/high_value_targets.txt") alvos ranqueados (payments=$(count "$OUT/hv_payments.txt") admin=$(count "$OUT/hv_admin.txt") api=$(count "$OUT/hv_api.txt") auth=$(count "$OUT/hv_auth.txt") data=$(count "$OUT/hv_data.txt"))"
  db_log high_value awk ok "$OUT/high_value_targets.txt" \
    "ranked=$(count "$OUT/high_value_targets.txt") payments=$(count "$OUT/hv_payments.txt") api=$(count "$OUT/hv_api.txt")" 0
  stamp "$OUT/high_value_targets.txt" high-value
}

# =============================================================================
#  FASE 6 — RELATÓRIO
# =============================================================================
phase_report() {
  local top
  top="$(head -n 40 "$OUT/high_value_targets_scored.tsv" 2>/dev/null || true)"

  cat > "$OUT/SUMMARY.md" <<EOF
# Recon Summary — ${TARGET}

- **Executado em**: $(date -u '+%Y-%m-%dT%H:%M:%SZ')
- **Script**: ${SELF} v${VERSION}
- **Alvo**: \`${TARGET}\` (domínio \`${DOMAIN}\`)
- **Auth**: $([[ ${#HDRS[@]} -gt 0 ]] && echo "${#HDRS[@]} header(s) de \`${AUTH_FILE}\`" || echo "anônimo (sem auth_headers.txt)")
- **Paralelismo**: ${THREADS} workers
- **Perfil**: ${PROFILE_LABEL} | ports=${PORTS_MODE} | katana=$( [[ "$KATANA_MAX_HOSTS" == "0" ]] && echo "todos os hosts" || echo "${KATANA_MAX_HOSTS} hosts" ) depth=${KATANA_DEPTH} | brute=$( [[ $SKIP_BRUTE -eq 1 ]] && echo off || echo on ) | jsluice=$( [[ $KATANA_JSLUICE -eq 1 ]] && echo on || echo off )
- **Histórico**: $( [[ $SKIP_HISTORY -eq 1 ]] && echo "pulado" || echo "domínio inteiro (wayback + gau)" )

## Números

| Artefato | Linhas |
|---|---|
| subdomains.txt | $(count "$OUT/subdomains.txt") |
| live.txt | $(count "$OUT/live.txt") |
| endpoints.txt | $(count "$OUT/endpoints.txt") |
| endpoints_params.txt | $(count "$OUT/endpoints_params.txt") |
| endpoints_api.txt | $(count "$OUT/endpoints_api.txt") |
| js_files.txt | $(count "$OUT/js_files.txt") |
| js_endpoints.txt | $(count "$OUT/js_endpoints.txt") |
| js_secrets.txt | $(count "$OUT/js_secrets.txt") |
| params_all.txt | $(count "$OUT/params_all.txt") |
| high_value_targets.txt | $(count "$OUT/high_value_targets.txt") |

## Top alvos de alto valor (score / keywords / URL)

\`\`\`
${top:-<sem resultados>}
\`\`\`

## Buckets

- \`hv_payments.txt\` — $(count "$OUT/hv_payments.txt") URLs
- \`hv_admin.txt\` — $(count "$OUT/hv_admin.txt") URLs
- \`hv_api.txt\` — $(count "$OUT/hv_api.txt") URLs
- \`hv_auth.txt\` — $(count "$OUT/hv_auth.txt") URLs
- \`hv_data.txt\` — $(count "$OUT/hv_data.txt") URLs

## Próximos passos (Portão Humano)

1. **Não** rode nuclei/dalfox em massa. A validação é cirúrgica.
2. Abra o alvo no browser com Interceptor → tráfego no Caido (127.0.0.1:8080).
3. No Caido MCP: baseline → \`caido_race_pipeline\` → leitura de estado (delta).
4. Prioridade: \`hv_payments.txt\` e \`hv_admin.txt\` (dinheiro e authz).
5. Registre cada hipótese em \`vulns\` (status \`lead\`) antes de testar.
6. Aplique \`skill_adversarial_validation_loop.md\` antes de qualquer \`confirmed\`.

## Logs

\`logs/\` contém cópias timestampadas por ferramenta (Unix \`${TS}\`).
EOF

  log "relatório: ${OUT}/SUMMARY.md"
  db_log report summary ok "$OUT/SUMMARY.md" "done" 0
}


# =============================================================================
#  MULTI-TARGET — normalização, lista persistida e menu interativo
# =============================================================================
TARGETS=()
SELECTED=()
BATCH_ROWS=()
LAST_BATCH_DIR=""

onoff() { (( $1 )) && printf 'on' || printf 'off'; }

# Aceita https://, porta, wildcard (*.example.com → example.com), maiúsculas
normalize_target() {
  local t="$1"
  t="${t#http://}"; t="${t#https://}"
  t="${t%%/*}"; t="${t%%:*}"; t="${t%.}"
  t="${t#\*.}"; t="${t#.}"
  t="$(printf '%s' "$t" | tr 'A-Z' 'a-z' | tr -d '[:space:]')"
  [[ -n "$t" ]] || return 1
  [[ "$t" == *.* ]] || return 1          # exige domínio (evita lixo tipo "does")
  [[ "$t" =~ ^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$ ]] || return 1
  [[ "$t" == *..* ]] && return 1
  printf '%s' "$t"
}

target_in_list() {
  local needle="$1" t
  for t in "${TARGETS[@]+"${TARGETS[@]}"}"; do
    [[ "$t" == "$needle" ]] && return 0
  done
  return 1
}

add_target() {
  local raw="$1" norm
  [[ -n "$raw" ]] || return 1
  if ! norm="$(normalize_target "$raw")"; then
    warn "alvo inválido ignorado: '${raw}'"
    return 1
  fi
  if target_in_list "$norm"; then
    log "duplicado ignorado: ${norm}"
    return 0
  fi
  [[ "$raw" == \** ]] && log "wildcard: '${raw}' → raiz '${norm}'"
  TARGETS+=("$norm")
  log "target: ${norm}"
  return 0
}

# 1 alvo por linha; '#' comenta; aceita vírgula/espaço; [quiet] silencia o log
load_targets_file() {
  local f="$1" quiet="${2:-}" line tok norm
  if [[ ! -s "$f" ]]; then
    warn "lista não encontrada ou vazia: ${f}"
    return 1
  fi
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%$'\r'}"
    [[ "$line" =~ ^[[:space:]]*# ]] && continue
    [[ -z "${line//[[:space:]]/}" ]] && continue
    line="${line//,/ }"
    for tok in $line; do
      if ! norm="$(normalize_target "$tok")"; then
        warn "alvo inválido ignorado em ${f}: '${tok}'"
        continue
      fi
      if ! target_in_list "$norm"; then
        TARGETS+=("$norm")
        [[ "$quiet" == quiet ]] || log "target: ${norm}"
      fi
    done
  done < "$f"
  return 0
}

save_targets_file() {
  mkdir -p "$(dirname "$TARGETS_FILE")" 2>/dev/null || true
  {
    printf '# recon_high_end — lista de targets (gerada em %s)\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    printf '# wildcard (*.dominio) é normalizado para a raiz; # comenta a linha\n'
    printf '%s\n' "${TARGETS[@]+"${TARGETS[@]}"}"
  } > "$TARGETS_FILE" 2>/dev/null || warn "não consegui salvar ${TARGETS_FILE}"
  return 0
}

# Remove alvo filho quando o pai já está na lista (evita recon duplicado)
dedupe_targets() {
  local t o covered keep=()
  for t in "${TARGETS[@]+"${TARGETS[@]}"}"; do
    covered=0
    for o in "${TARGETS[@]+"${TARGETS[@]}"}"; do
      [[ "$t" == "$o" ]] && continue
      if [[ "$t" == *".${o}" ]]; then covered=1; break; fi
    done
    if (( covered )); then
      log "dedupe: ${t} (coberto por ${o})"
    else
      keep+=("$t")
    fi
  done
  TARGETS=("${keep[@]+"${keep[@]}"}")
  return 0
}

scope_check_target() {
  local t="$1" root
  [[ -f "$SCOPE_FILE" ]] || return 0
  root="$t"
  [[ "$t" == *.*.* ]] && root="${t#*.}"
  grep -qiF -- "$t" "$SCOPE_FILE" && return 0
  grep -qiF -- "$root" "$SCOPE_FILE" && return 0
  return 1
}
scope_check() { scope_check_target "$TARGET"; }

print_plan() {
  local t st i=0
  printf '\nPLANO — %d alvo(s) | threads=%s | perfil=%s | ports=%s | katana=%s depth=%s chunk=%s | jsl=%s aff=%s escopo=%s | brute=%s | fresh=%s | force=%s\n' \
    "${#TARGETS[@]}" "$THREADS" "$PROFILE_LABEL" "$PORTS_MODE" \
    "$([[ "$KATANA_MAX_HOSTS" == "0" ]] && echo all || echo "$KATANA_MAX_HOSTS")" \
    "$KATANA_DEPTH" "$KATANA_CHUNK" \
    "$(onoff "$KATANA_JSLUICE")" "$(onoff "$KATANA_AFF")" "$KATANA_FS" \
    "$([[ $SKIP_BRUTE -eq 1 ]] && echo off || echo on)" \
    "$(onoff "$FRESH")" "$(onoff "$FORCE")"
  printf '  %-3s %-48s %-8s %s\n' "#" "target" "scope" "output"
  for t in "${TARGETS[@]}"; do
    i=$((i + 1))
    if scope_check_target "$t"; then
      st="ok"
    elif (( FORCE )); then
      st="force"
    else
      st="FORA"
    fi
    printf '  %-3d %-48s %-8s %s\n' "$i" "$t" "$st" "${DOCS_ROOT}/${t}"
  done
  printf '\nNenhum request foi feito (--plan).\n\n'
  return 0
}

# Aceita "1 3 4-6" ou vazio (= todos). Preenche SELECTED.
parse_selection() {
  local input="${1//,/ }" part a b i t dup
  SELECTED=()
  if [[ -z "${input//[[:space:]]/}" ]]; then
    SELECTED=("${TARGETS[@]+"${TARGETS[@]}"}")
    return 0
  fi
  for part in $input; do
    if [[ "$part" =~ ^([0-9]+)-([0-9]+)$ ]]; then
      a=${BASH_REMATCH[1]}; b=${BASH_REMATCH[2]}
      (( a > b )) && { t=$a; a=$b; b=$t; }
      for ((i = a; i <= b; i++)); do
        if (( i >= 1 && i <= ${#TARGETS[@]} )); then
          t="${TARGETS[$((i - 1))]}"
          dup=0
          for part in "${SELECTED[@]+"${SELECTED[@]}"}"; do [[ "$part" == "$t" ]] && dup=1; done
          (( dup )) || SELECTED+=("$t")
        fi
      done
    elif [[ "$part" =~ ^[0-9]+$ ]]; then
      if (( part >= 1 && part <= ${#TARGETS[@]} )); then
        t="${TARGETS[$((part - 1))]}"
        dup=0
        for a in "${SELECTED[@]+"${SELECTED[@]}"}"; do [[ "$a" == "$t" ]] && dup=1; done
        (( dup )) || SELECTED+=("$t")
      else
        warn "índice fora da lista: ${part}"
      fi
    else
      warn "seleção inválida: ${part}"
    fi
  done
  (( ${#SELECTED[@]} )) || return 1
  return 0
}

remove_target() {
  local sel="$1" i norm t new=() found=0
  if [[ "$sel" =~ ^[0-9]+$ ]]; then
    i=$((sel - 1))
    if (( i >= 0 && i < ${#TARGETS[@]} )); then
      log "removido: ${TARGETS[$i]}"
      TARGETS=("${TARGETS[@]:0:$i}" "${TARGETS[@]:$((i + 1))}")
    else
      warn "índice inválido: ${sel}"
    fi
    return 0
  fi
  if ! norm="$(normalize_target "$sel")"; then
    warn "alvo inválido: ${sel}"
    return 1
  fi
  for t in "${TARGETS[@]+"${TARGETS[@]}"}"; do
    if [[ "$t" == "$norm" ]]; then found=1; else new+=("$t"); fi
  done
  if (( found )); then
    TARGETS=("${new[@]+"${new[@]}"}")
    log "removido: ${norm}"
  else
    warn "não está na lista: ${norm}"
  fi
  return 0
}

# ═══════════════════════════════════════════════════════════════════════════
#  UI — tema Berserk (sangue/osso), caixas, tabela e cards
# ═══════════════════════════════════════════════════════════════════════════
UI_CONF="${UI_CONF:-/home/hack/targets/recon_ui.conf}"
THEME="${THEME:-berserk}"
UI_BORDER=""; UI_TXT=""; UI_DIM=""; UI_HDR=""; UI_ACC=""; UI_RST=""

ui_load_conf() {
  [[ -r "$UI_CONF" ]] || return 0
  local k v
  while IFS='=' read -r k v; do
    case "$k" in
      THEME) [[ -n "$v" ]] && THEME="$v" ;;
    esac
  done < <(grep -E '^THEME=' "$UI_CONF" 2>/dev/null)
  return 0
}

ui_save_conf() {
  mkdir -p "$(dirname "$UI_CONF")" 2>/dev/null || true
  printf 'THEME=%s\n' "$THEME" > "$UI_CONF" 2>/dev/null || true
}

ui_theme_set() {
  UI_BORDER=""; UI_TXT=""; UI_DIM=""; UI_HDR=""; UI_ACC=""; UI_RST=""
  C_OK=""; C_WARN=""; C_ERR=""; C_HDR=""; C_RST=""
  if [[ -t 1 ]]; then
    case "${THEME:-berserk}" in
      berserk)  # sangue seco, osso e aço
        UI_BORDER=$'\033[38;5;238m'; UI_TXT=$'\033[38;5;223m'; UI_DIM=$'\033[38;5;245m'
        UI_HDR=$'\033[38;5;160m'; UI_ACC=$'\033[38;5;196m'; UI_RST=$'\033[0m'
        C_HDR=$'\033[38;5;160m'; C_OK=$'\033[38;5;223m'
        C_WARN=$'\033[38;5;214m'; C_ERR=$'\033[38;5;196m'; C_RST=$'\033[0m' ;;
      matrix)
        UI_BORDER=$'\033[38;5;22m'; UI_TXT=$'\033[38;5;46m'; UI_DIM=$'\033[38;5;28m'
        UI_HDR=$'\033[38;5;46m'; UI_ACC=$'\033[38;5;82m'; UI_RST=$'\033[0m'
        C_HDR=$'\033[38;5;46m'; C_OK=$'\033[38;5;82m'
        C_WARN=$'\033[38;5;118m'; C_ERR=$'\033[38;5;196m'; C_RST=$'\033[0m' ;;
      cyber)
        UI_BORDER=$'\033[38;5;24m'; UI_TXT=$'\033[38;5;51m'; UI_DIM=$'\033[38;5;31m'
        UI_HDR=$'\033[38;5;201m'; UI_ACC=$'\033[38;5;207m'; UI_RST=$'\033[0m'
        C_HDR=$'\033[38;5;201m'; C_OK=$'\033[38;5;51m'
        C_WARN=$'\033[38;5;214m'; C_ERR=$'\033[38;5;196m'; C_RST=$'\033[0m' ;;
      *) ;; # mono: sem cor
    esac
  fi
  return 0
}

ui_width() {
  local w="${UI_WIDTH:-0}"
  if [[ "$w" == "0" || -z "$w" ]]; then w="$(tput cols 2>/dev/null || echo 68)"; fi
  [[ "$w" =~ ^[0-9]+$ ]] || w=68
  (( w < 64 )) && w=64
  (( w > 100 )) && w=100
  printf '%s' "$w"
}

ui_pad() { local ch="$1" n="$2" i; for ((i = 0; i < n; i++)); do printf '%s' "$ch"; done; }

ui_top()    { [[ -t 1 ]] || return 0; local w; w=$(ui_width); printf '%s╔' "$UI_BORDER"; ui_pad '═' $((w - 2)); printf '╗%s\n' "$UI_RST"; }
ui_sep()    { [[ -t 1 ]] || return 0; local w; w=$(ui_width); printf '%s╠' "$UI_BORDER"; ui_pad '═' $((w - 2)); printf '╣%s\n' "$UI_RST"; }
ui_bottom() { [[ -t 1 ]] || return 0; local w; w=$(ui_width); printf '%s╚' "$UI_BORDER"; ui_pad '═' $((w - 2)); printf '╝%s\n' "$UI_RST"; }
ui_thin()   { [[ -t 1 ]] || return 0; local w; w=$(ui_width); printf '%s╟' "$UI_BORDER"; ui_pad '─' $((w - 2)); printf '╢%s\n' "$UI_RST"; }

ui_row() {  # linha simples (texto plano)
  [[ -t 1 ]] || return 0
  local text="$1" w pad max
  w=$(ui_width); max=$(( w - 4 )); (( ${#text} > max )) && text="${text:0:max}"
  pad=$(( w - 4 - ${#text} )); (( pad < 0 )) && pad=0
  printf '%s║%s %s%*s %s║%s\n' "$UI_BORDER" "$UI_RST" "$text" "$pad" "" "$UI_BORDER" "$UI_RST"
}

ui_row2() { # esquerda (normal) + direita (dim)
  [[ -t 1 ]] || return 0
  local l="$1" r="$2" w gap max
  w=$(ui_width); max=$(( w - 8 - ${#r} )); (( max < 8 )) && max=8
  (( ${#l} > max )) && l="${l:0:max}"
  gap=$(( w - 6 - ${#l} - ${#r} )); (( gap < 1 )) && gap=1
  printf '%s║%s %s%*s%s%s%s ║%s\n' "$UI_BORDER" "$UI_RST" "$l" "$gap" "" "$UI_DIM" "$r" "$UI_BORDER" "$UI_RST"
}

ui_card() { # titulo, linhas...
  [[ -t 1 ]] || return 0
  local title="$1"; shift
  ui_top
  ui_row2 "† ${title}" ""
  ui_thin
  local l
  for l in "$@"; do ui_row "  ${l}"; done
  ui_bottom
}

ui_header() {
  [[ -t 1 ]] || return 0
  ui_top
  ui_row2 "☠  HACKBOT · RECON" "« STRUGGLE »  v${VERSION}"
  ui_row2 "$(date +%H:%M) · ${DOCS_ROOT} · ${#TARGETS[@]} alvo(s)" "tema: ${THEME} · perfil: ${PROFILE_LABEL}"
  ui_bottom
  printf '\n'
}

ui_targets_table() {
  [[ -t 1 ]] || return 0
  local w i t sc st last line col hdr
  w=$(ui_width)
  ui_top
  ui_row2 "ALVOS (${#TARGETS[@]})" "docs: ${DOCS_ROOT}"
  ui_thin

  hdr=$(printf ' %-3s %-36s %-8s %-9s %s' "#" "alvo" "escopo" "estado" "ultimo")
  printf '%s║%s%s%-*.*s%s║%s\n' "$UI_BORDER" "$UI_RST" "$UI_DIM" "$((w - 2))" "$((w - 2))" "$hdr" "$UI_RST" "$UI_BORDER"
  ui_thin

  if (( ${#TARGETS[@]} == 0 )); then
    line=" (lista vazia — a/[1] para adicionar)"
    printf '%s║%s%s%-*.*s%s║%s\n' "$UI_BORDER" "$UI_RST" "$UI_DIM" "$((w - 2))" "$((w - 2))" "$line" "$UI_RST" "$UI_BORDER"
  else
    for i in "${!TARGETS[@]}"; do
      t="${TARGETS[$i]}"
      if scope_check_target "$t"; then sc="ok"; col="$UI_TXT"; else sc="FORA"; col="$UI_ACC"; fi
      [[ -d "${DOCS_ROOT}/${t}" ]] && st="existe" || st="novo"
      last="—"
      if [[ -f "${DOCS_ROOT}/${t}/SUMMARY.md" ]]; then
        last="$(date -r "${DOCS_ROOT}/${t}/SUMMARY.md" +%H:%M 2>/dev/null || echo '—')"
      fi
      line=$(printf ' %-3d %-36s %-8s %-9s %s' "$((i + 1))" "$t" "$sc" "$st" "$last")
      printf '%s║%s%s%-*.*s%s║%s\n' "$UI_BORDER" "$UI_RST" "$col" "$((w - 2))" "$((w - 2))" "$line" "$UI_RST" "$UI_BORDER"
    done
  fi
  ui_bottom
  printf '%s' "$UI_RST"
}

ui_actions() {
  [[ -t 1 ]] || return 0
  ui_top
  ui_row " [1] + alvo        [2] ^ importar      [3] x remover      [4] - limpar"
  ui_row " [5] » TODOS       [6] » seleção       [7] * opções       [8] # pastas"
  ui_row " [0] » sair        t: trocar tema (${THEME})"
  ui_bottom
}

ui_footer() {
  [[ -t 1 ]] || return 0
  printf ' %sperfil:%s %s · ports %s · katana %s · chunk %s · jsl %s · aff %s · escopo %s · brute %s\n' \
    "$UI_HDR" "$UI_RST" "$PROFILE_LABEL" "$PORTS_MODE" \
    "$([[ "$KATANA_MAX_HOSTS" == "0" ]] && echo all || echo "$KATANA_MAX_HOSTS")" \
    "$KATANA_CHUNK" "$(onoff "$KATANA_JSLUICE")" "$(onoff "$KATANA_AFF")" "$KATANA_FS" \
    "$([[ $SKIP_BRUTE -eq 1 ]] && echo off || echo on)"
  printf ' %satalhos:%s a add · i import · x remover · r rodar · s seleção · o opções · p pastas · t tema · q sair\n' \
    "$UI_DIM" "$UI_RST"
}

ui_theme_cycle() {
  case "${THEME:-berserk}" in
    berserk) THEME=matrix ;;
    matrix)  THEME=cyber ;;
    cyber)   THEME=mono ;;
    *)       THEME=berserk ;;
  esac
  ui_theme_set
  ui_save_conf
  return 0
}

set_profile_deep() {
  DEEP=1; PROFILE_LABEL="DEEP"
  PORTS_MODE=full; KATANA_MAX_HOSTS=0; KATANA_DEPTH=3; KATANA_JSLUICE=0
  KATANA_AFF=0; KATANA_FS=fqdn; KATANA_CHUNK=10
  SKIP_BRUTE=0; MAX_PERMUTATIONS=20000; PERM_INPUT=4000
  MAX_JS=6000; MAX_ARJUN=50; KATANA_CHUNK_TIMEOUT=300
  KATANA_MAX_URLS_PER_CHUNK=30000; SUBFINDER_MAX_TIME=8
}

set_profile_default() {
  DEEP=0; PROFILE_LABEL="default"
  PORTS_MODE=quick; KATANA_MAX_HOSTS=120; KATANA_DEPTH=3; KATANA_JSLUICE=0
  KATANA_AFF=0; KATANA_FS=fqdn; KATANA_CHUNK=25
  SKIP_BRUTE=1; MAX_PERMUTATIONS=6000; PERM_INPUT=1500
  MAX_JS=3000; MAX_ARJUN=15; KATANA_CHUNK_TIMEOUT=240
  SUBFINDER_MAX_TIME=3
}

mark_custom() { DEEP=0; PROFILE_LABEL="custom"; }

settings_menu() {
  local opt val
  while true; do
    printf '\n  %s† OPÇÕES%s\n' "$UI_HDR" "$UI_RST"
    printf '   1) threads ............ %s\n' "$THREADS"
    printf '   2) perfil DEEP ........ %s\n' "$(onoff "$DEEP")"
    printf '   3) skip-brute ......... %s\n' "$(onoff "$SKIP_BRUTE")"
    printf '   4) ports mode ......... %s\n' "$PORTS_MODE"
    printf '   5) katana hosts ....... %s\n' "$([[ "$KATANA_MAX_HOSTS" == "0" ]] && echo todos || echo "$KATANA_MAX_HOSTS")"
    printf '   6) katana depth ....... %s\n' "$KATANA_DEPTH"
    printf '   7) katana chunk ....... %s\n' "$KATANA_CHUNK"
    printf '   8) skip-history ....... %s\n' "$(onoff "$SKIP_HISTORY")"
    printf '   9) skip-arjun ......... %s\n' "$(onoff "$SKIP_ARJUN")"
    printf '  10) skip-chaos ......... %s\n' "$(onoff "$SKIP_CHAOS")"
    printf '  11) fresh .............. %s\n' "$(onoff "$FRESH")"
    printf '  12) force (scope) ...... %s\n' "$(onoff "$FORCE")"
    printf '  13) tema ............... %s\n' "$THEME"
    printf '  14) katana jsl ......... %s\n' "$(onoff "$KATANA_JSLUICE")"
    printf '  15) katana aff ......... %s\n' "$(onoff "$KATANA_AFF")"
    printf '  16) katana escopo ...... %s\n' "$KATANA_FS"
    printf '  17) katana fsu ......... %s\n' "$(onoff "$KATANA_FSU")"
    printf '  18) katana teto/chunk .. %s\n' "$KATANA_MAX_URLS_PER_CHUNK"
    printf '   0) voltar\n'
    read -rp "  opção> " opt || return 0
    case "$opt" in
      1) read -rp "  threads [${THREADS}]: " val || continue
         if [[ "$val" =~ ^[0-9]+$ ]] && (( val > 0 )); then THREADS="$val"; else warn "valor inválido"; fi ;;
      2) if (( DEEP )); then
           set_profile_default
           log "perfil: default (rápido)"
         else
           set_profile_deep
           log "perfil: DEEP (cobertura total — vai demorar)"
         fi ;;
      3) SKIP_BRUTE=$((1 - SKIP_BRUTE)); mark_custom ;;
      4) case "$PORTS_MODE" in quick) PORTS_MODE=full ;; full) PORTS_MODE=none ;; *) PORTS_MODE=quick ;; esac; mark_custom ;;
      5) read -rp "  katana hosts [${KATANA_MAX_HOSTS}] (0=todos): " val || continue
         if [[ "$val" =~ ^[0-9]+$ ]]; then KATANA_MAX_HOSTS="$val"; mark_custom; else warn "valor inválido"; fi ;;
      6) read -rp "  katana depth [${KATANA_DEPTH}]: " val || continue
         if [[ "$val" =~ ^[0-9]+$ ]] && (( val >= 1 && val <= 10 )); then KATANA_DEPTH="$val"; mark_custom; else warn "1-10"; fi ;;
      7) read -rp "  katana chunk [${KATANA_CHUNK}]: " val || continue
         if [[ "$val" =~ ^[0-9]+$ ]] && (( val >= 5 && val <= 200 )); then KATANA_CHUNK="$val"; mark_custom; else warn "5-200"; fi ;;
      8) SKIP_HISTORY=$((1 - SKIP_HISTORY)); mark_custom ;;
      9) SKIP_ARJUN=$((1 - SKIP_ARJUN)); mark_custom ;;
      10) SKIP_CHAOS=$((1 - SKIP_CHAOS)); mark_custom ;;
      11) FRESH=$((1 - FRESH)) ;;
      12) FORCE=$((1 - FORCE)) ;;
      13) ui_theme_cycle; log "tema: ${THEME}" ;;
      14) KATANA_JSLUICE=$((1 - KATANA_JSLUICE)); mark_custom ;;
      15) KATANA_AFF=$((1 - KATANA_AFF)); mark_custom ;;
      16) case "$KATANA_FS" in fqdn) KATANA_FS=rdn ;; *) KATANA_FS=fqdn ;; esac; mark_custom ;;
      17) KATANA_FSU=$((1 - KATANA_FSU)); mark_custom ;;
      18) read -rp "  teto de URLs por chunk [${KATANA_MAX_URLS_PER_CHUNK}]: " val || continue
         if [[ "$val" =~ ^[0-9]+$ ]] && (( val >= 1000 )); then KATANA_MAX_URLS_PER_CHUNK="$val"; mark_custom; else warn "mínimo 1000"; fi ;;
      0|"") return 0 ;;
      *) warn "opção inválida: ${opt}" ;;
    esac
  done
}

paths_menu() {
  local i t full st idx
  printf '\n  %s† PASTAS EM %s%s\n\n' "$UI_HDR" "$DOCS_ROOT" "$UI_RST"
  if (( ${#TARGETS[@]} )); then
    printf '   %-3s %-34s %-8s %-6s %s\n' "#" "target" "estado" "scope" "pasta"
    for i in "${!TARGETS[@]}"; do
      t="${TARGETS[$i]}"; full="${DOCS_ROOT}/${t}"
      if [[ -d "$full" ]]; then st="existe"; else st="novo"; fi
      if scope_check_target "$t"; then
        printf '   %-3d %-34s %-8s %-6s %s\n' "$((i + 1))" "$t" "$st" "ok" "$full"
      else
        printf '   %-3d %-34s %-8s %-6s %s\n' "$((i + 1))" "$t" "$st" "FORA" "$full"
      fi
    done
  else
    printf '   (lista vazia)\n'
  fi

  if [[ -n "${LAST_BATCH_DIR:-}" && -d "$LAST_BATCH_DIR" ]]; then
    printf '\n   último lote: %s/SUMMARY.md\n' "$LAST_BATCH_DIR"
  fi

  printf '\n   Enter para voltar, ou nº do alvo para imprimir só o caminho.\n'
  read -rp "  nº> " idx || return 0
  if [[ "$idx" =~ ^[0-9]+$ ]] && (( idx >= 1 && idx <= ${#TARGETS[@]} )); then
    printf '%s\n' "${DOCS_ROOT}/${TARGETS[$((idx - 1))]}"
  fi
  return 0
}

menu() {
  local opt line tok
  while true; do
    printf '\n'
    ui_header
    ui_targets_table
    printf '\n'
    ui_actions
    printf '\n'
    ui_footer
    read -rp "  ${UI_ACC}†${UI_RST} opção> " opt || return 0

    case "$opt" in
      1|a|A)
        read -rp "  targets (espaço/vírgula, aceita *.dominio): " line || continue
        line="${line//,/ }"
        for tok in $line; do add_target "$tok" || true; done
        save_targets_file
        ;;
      2|i|I)
        read -rp "  arquivo [${TARGETS_FILE}]: " line || continue
        line="${line:-$TARGETS_FILE}"
        load_targets_file "$line" || true
        save_targets_file
        ;;
      3|x|X)
        read -rp "  nº ou domínio para remover: " line || continue
        remove_target "$line" || true
        save_targets_file
        ;;
      4|c|C)
        read -rp "  limpar TODA a lista? (s/N): " line || continue
        if [[ "$line" =~ ^[sSyY]$ ]]; then
          TARGETS=(); save_targets_file; log "lista limpa"
        fi
        ;;
      5|r|R)
        if (( ${#TARGETS[@]} )); then
          run_batch "${TARGETS[@]}" || true
        else
          warn "lista vazia"
        fi
        save_targets_file
        ;;
      6|s|S)
        if (( ${#TARGETS[@]} == 0 )); then
          warn "lista vazia"; continue
        fi
        read -rp "  índices (ex: 1 3 4-6; vazio = todos): " line || continue
        if parse_selection "$line"; then
          run_batch "${SELECTED[@]}" || true
        fi
        ;;
      7|o|O) settings_menu ;;
      8|p|P) paths_menu ;;
      t|T) ui_theme_cycle; log "tema: ${THEME}" ;;
      0|q|Q|sair) return 0 ;;
      "") ;;
      *) warn "opção inválida: ${opt}" ;;
    esac
  done
}

# =============================================================================
#  EXECUÇÃO — 1 alvo ou lote sequencial
# =============================================================================
run_one_target() {
  local t="$1" t0=$SECONDS
  TARGET="$t"; DOMAIN="$t"
  OUT="${DOCS_ROOT}/${TARGET}"
  LOGS="${OUT}/logs"
  LOG="${LOGS}/recon-${TS}.log"
  JS_DIR="${OUT}/js"
  JS_MANIFEST="${OUT}/.js_manifest.tsv"
  ARJUN_DIR="${OUT}/arjun"

  if ! scope_check; then
    if (( FORCE )); then
      warn "${TARGET} fora do scope.md — seguindo por --force"
    else
      warn "${TARGET} fora do scope.md — pulando (use --force se autorizado)"
      db_log batch "$TARGET" skipped "" "out-of-scope" 0
      BATCH_ROWS+=("${TARGET}|skip|0|0|0|0|0")
      return 3
    fi
  fi

  if (( FRESH )) && [[ -d "$OUT" ]]; then
    if [[ "$OUT" != "${DOCS_ROOT}/"* ]]; then
      warn "recusando rm -rf em ${OUT}"
      return 1
    fi
    rm -rf "$OUT"
  fi

  mkdir -p "$OUT" "$LOGS" "$JS_DIR" "$ARJUN_DIR" /tmp/opencode
  HV_AWK="$(mktemp /tmp/opencode/hv-XXXXXX.awk)"
  backup_existing
  PHASE_N=0

  if [[ -t 1 ]]; then
    ui_card "PRÉ-VOO · ${TARGET}" \
      "perfil    ${PROFILE_LABEL}$( [[ $DEEP -eq 1 ]] && echo ' (deep)' || echo ' (rápido)' )" \
      "ports     ${PORTS_MODE} · katana $( [[ "$KATANA_MAX_HOSTS" == "0" ]] && echo todos || echo "${KATANA_MAX_HOSTS} hosts" ) · depth ${KATANA_DEPTH}" \
      "katana    chunk ${KATANA_CHUNK} · jsl $(onoff "$KATANA_JSLUICE") · aff $(onoff "$KATANA_AFF") · escopo ${KATANA_FS}" \
      "escopo    ok · bruteforce $( [[ $SKIP_BRUTE -eq 1 ]] && echo off || echo on )" \
      "saída     ${OUT}" \
      "estimado  $( [[ $DEEP -eq 1 ]] && echo '1.5-2.5 h' || echo '30-45 min (alvo grande)' )"
  fi

  # variáveis usadas pelos filhos de xargs -P
  export JS_DIR JS_MANIFEST ARJUN_DIR DOMAIN HDR_BLOB AUTH_RC

  log "════════════════════════════════════════════════════════════"
  log "recon_high_end v${VERSION} | alvo=${TARGET} | threads=${THREADS}"
  log "saída=${OUT}"
  log "════════════════════════════════════════════════════════════"

  run_phase "asset-discovery" phase_asset
  run_phase "ports-http"      phase_ports_http
  run_phase "content"         phase_content
  run_phase "js-analysis"     phase_js
  run_phase "params"          phase_params
  run_phase "high-value"      phase_high_value
  run_phase "report"          phase_report

  local dur=$((SECONDS - t0))
  log "FIM ${TARGET} em ${dur}s — subdomains=$(count "$OUT/subdomains.txt") live=$(count "$OUT/live.txt") endpoints=$(count "$OUT/endpoints.txt") high-value=$(count "$OUT/high_value_targets.txt")"

  if [[ -t 1 ]]; then
    ui_card "RESULTADO · ${TARGET}" \
      "subs $(count "$OUT/subdomains.txt") · live $(count "$OUT/live.txt") · endpoints $(count "$OUT/endpoints.txt") · high-value $(count "$OUT/high_value_targets.txt")" \
      "js $(count "$OUT/js_endpoints.txt") rotas · $(count "$OUT/js_secrets.txt") segredos · $(count "$OUT/endpoints_api.txt") rotas de API" \
      "resumo ${OUT}/SUMMARY.md"
  fi

  BATCH_ROWS+=("${TARGET}|ok|$(count "$OUT/subdomains.txt")|$(count "$OUT/live.txt")|$(count "$OUT/endpoints.txt")|$(count "$OUT/high_value_targets.txt")|$(count "$OUT/js_secrets.txt")")
  db_log batch "$TARGET" done "$OUT" \
    "subs=$(count "$OUT/subdomains.txt") live=$(count "$OUT/live.txt") hv=$(count "$OUT/high_value_targets.txt")" "$dur"
  [[ -n "${HV_AWK:-}" && -f "$HV_AWK" ]] && rm -f "$HV_AWK"
  return 0
}

write_batch_summary() {
  local dir="$1" ok="$2" fail="$3" skip="$4" row t st s l e h sec
  mkdir -p "$dir" 2>/dev/null || true
  {
    printf '# Batch recon — %s\n\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    printf -- '- Alvos: %d | ok: %d | falha: %d | pulados: %d\n' "$((ok + fail + skip))" "$ok" "$fail" "$skip"
    printf -- '- Threads: %s | fresh: %s | force: %s\n\n' "$THREADS" "$(onoff "$FRESH")" "$(onoff "$FORCE")"
    printf '| target | status | subs | live | endpoints | high-value | secrets |\n'
    printf '|---|---|---|---|---|---|---|\n'
    for row in "${BATCH_ROWS[@]+"${BATCH_ROWS[@]}"}"; do
      IFS='|' read -r t st s l e h sec <<< "$row"
      printf '| %s | %s | %s | %s | %s | %s | %s |\n' "$t" "$st" "$s" "$l" "$e" "$h" "$sec"
    done
    printf '\nDetalhes por alvo: `docs/<target>/SUMMARY.md`. Validação é cirúrgica via Caido MCP.\n'
  } > "$dir/SUMMARY.md" 2>/dev/null || warn "não consegui escrever ${dir}/SUMMARY.md"
  return 0
}

run_batch() {
  local list=("$@") t rc ok=0 fail=0 skip=0
  local t0=$SECONDS
  if (( ${#list[@]} == 0 )); then warn "sem alvos para rodar"; return 1; fi

  BATCH_ROWS=()
  local batch_dir="${DOCS_ROOT}/_batch-${TS}"
  local batch_log="${batch_dir}/recon-batch.log"
  mkdir -p "$batch_dir" /tmp/opencode
  LAST_BATCH_DIR="$batch_dir"
  LOG="$batch_log"

  # Dedupe em runtime: filho coberto por um pai da MESMA execução não roda de novo.
  # Não altera a lista salva no menu.
  local deduped=() t2 o2 covered2
  for t2 in "${list[@]}"; do
    covered2=0
    for o2 in "${list[@]}"; do
      [[ "$t2" == "$o2" ]] && continue
      if [[ "$t2" == *".${o2}" ]]; then covered2=1; break; fi
    done
    if (( covered2 )); then
      log "dedupe: ${t2} (coberto por ${o2})"
    else
      deduped+=("$t2")
    fi
  done
  list=("${deduped[@]+"${deduped[@]}"}")

  db_init
  load_auth
  export AUTH_RC

  log "BATCH: ${#list[@]} alvo(s) | threads=${THREADS} | fresh=$(onoff "$FRESH") | force=$(onoff "$FORCE")"
  if [[ -s "$AUTH_FILE" ]]; then
    log "BATCH: crawl autenticado habilitado (headers não são logados)"
  else
    log "BATCH: crawl anônimo (crie ${AUTH_FILE} para autenticar)"
  fi

  for t in "${list[@]}"; do
    LOG="$batch_log"
    rc=0
    run_one_target "$t" || rc=$?
    case "$rc" in
      0) ok=$((ok + 1)) ;;
      3) skip=$((skip + 1)) ;;
      *) fail=$((fail + 1)); BATCH_ROWS+=("${t}|fail|0|0|0|0|0") ;;
    esac
  done

  LOG="$batch_log"
  write_batch_summary "$batch_dir" "$ok" "$fail" "$skip"

  local dur=$((SECONDS - t0))
  log "BATCH concluído em ${dur}s | ok=${ok} falha=${fail} pulados=${skip}"
  if [[ -t 1 ]]; then
    ui_card "LOTE · $((ok + fail + skip)) ALVO(S)" \
      "ok ${ok} · falha ${fail} · pulados ${skip} · tempo $((dur / 60))m$((dur % 60))s" \
      "resumo ${batch_dir}/SUMMARY.md"
  fi
  if [[ -f "${batch_dir}/SUMMARY.md" ]]; then
    log "resumo: ${batch_dir}/SUMMARY.md"
  else
    warn "resumo do lote não foi gravado (pasta removida durante a execução?)"
  fi
  log "artefatos: ${DOCS_ROOT}/<target>/  (por alvo)"
  if (( skip > 0 )); then
    log "dica: ${skip} alvo(s) fora do scope — edite ${SCOPE_FILE} ou ative force=on em [7]"
  fi
  local bstatus="ok"
  (( fail > 0 )) && bstatus="partial"
  (( ok == 0 )) && bstatus="skip"
  local saved_target="$TARGET"
  TARGET="__batch__"
  db_log batch "__batch__" "$bstatus" "$batch_dir/SUMMARY.md" \
    "targets=${#list[@]} ok=${ok} fail=${fail} skip=${skip}" "$dur"
  TARGET="$saved_target"

  if (( ok == 0 )); then return 1; fi
  return 0
}

# =============================================================================
#  MAIN
# =============================================================================
main() {
  local positional=() files=() force_menu=0 plan=0 checkonly=0 p f

  while (( $# )); do
    case "$1" in
      -h|--help) usage; exit 0 ;;
      --threads) THREADS="${2:?--threads exige valor}"; shift 2 ;;
      --fresh) FRESH=1; shift ;;
      --force) FORCE=1; shift ;;
      --plan) plan=1; shift ;;
      --check-keys) checkonly=1; shift ;;
      --menu) force_menu=1; shift ;;
      --file) files+=("${2:?--file exige caminho}"); shift 2 ;;
      --skip-brute) SKIP_BRUTE=1; mark_custom; shift ;;
      --brute) SKIP_BRUTE=0; mark_custom; shift ;;
      --ports) PORTS_MODE="${2:?--ports exige modo}"; mark_custom; shift 2 ;;
      --deep) set_profile_deep; shift ;;
      --katana-hosts) KATANA_MAX_HOSTS="${2:?--katana-hosts exige valor}"; mark_custom; shift 2 ;;
      --katana-depth) KATANA_DEPTH="${2:?--katana-depth exige valor}"; mark_custom; shift 2 ;;
      --katana-chunk) KATANA_CHUNK="${2:?--katana-chunk exige valor}"; mark_custom; shift 2 ;;
      --skip-ports) SKIP_PORTS=1; mark_custom; shift ;;
      --skip-history) SKIP_HISTORY=1; shift ;;
      --skip-arjun) SKIP_ARJUN=1; shift ;;
      --skip-chaos) SKIP_CHAOS=1; shift ;;
      -*) die "flag desconhecida: $1 (use --help)" ;;
      *) positional+=("$1"); shift ;;
    esac
  done

  [[ "$THREADS" =~ ^[0-9]+$ ]] && (( THREADS > 0 )) || die "--threads inválido"
  case "$PORTS_MODE" in none|quick|full) ;; *) die "--ports inválido: ${PORTS_MODE} (none|quick|full)" ;; esac

  ui_load_conf
  ui_theme_set

  if (( DEEP )); then
    log "perfil DEEP: cobertura total (vai demorar)"
  fi

  print_banner

  if (( checkonly )); then
    check_keys
    return 0
  fi

  if (( force_menu )); then
    [[ -f "$TARGETS_FILE" ]] && load_targets_file "$TARGETS_FILE" quiet || true
    menu
    return 0
  fi

  # sem alvos → menu (lista persistida) quando em TTY
  if (( ${#positional[@]} == 0 && ${#files[@]} == 0 )); then
    if [[ -t 0 && -t 1 ]]; then
      [[ -f "$TARGETS_FILE" ]] && load_targets_file "$TARGETS_FILE" quiet || true
      menu
      return 0
    fi
    usage
    exit 2
  fi

  for p in "${positional[@]+"${positional[@]}"}"; do add_target "$p" || true; done
  for f in "${files[@]+"${files[@]}"}"; do load_targets_file "$f" || true; done

  (( ${#TARGETS[@]} )) || die "nenhum alvo válido"
  dedupe_targets
  (( ${#TARGETS[@]} )) || die "todos os alvos foram deduplicados"

  if (( plan )); then
    print_plan
    return 0
  fi

  run_batch "${TARGETS[@]}" || exit 1
  return 0
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
