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

VERSION="1.0.0"
SELF="$(basename "$0")"

# ── Configuração (sobrescreva por env) ───────────────────────────────────────
DOCS_ROOT="${DOCS_ROOT:-/home/hack/docs}"
DB_PATH="${DB_PATH:-/home/hack/opencode-pentester/db/findings.db}"
TARGETS_FILE="${TARGETS_FILE:-/home/hack/targets/recon_targets.txt}"
BANNER_FILE="${BANNER_FILE:-/home/hack/scripts/banner.txt}"
AUTH_FILE="${AUTH_FILE:-/home/hack/targets/auth_headers.txt}"
GH_TOKEN_FILE="${GH_TOKEN_FILE:-/home/hack/targets/github_token}"
SCOPE_FILE="${SCOPE_FILE:-/home/hack/targets/scope.md}"
RESOLVERS="${RESOLVERS:-/home/hack/wordlists/resolvers/resolvers.txt}"
DNS_WORDLIST="${DNS_WORDLIST:-/home/hack/wordlists/SecLists/Discovery/DNS/subdomains-top1million-110000.txt}"

THREADS="${THREADS:-10}"                 # paralelismo global
MAX_PERMUTATIONS="${MAX_PERMUTATIONS:-20000}"
MAX_JS="${MAX_JS:-4000}"                 # teto de arquivos JS baixados
MAX_ARJUN="${MAX_ARJUN:-25}"             # teto de origins para arjun
NAABU_TOP_PORTS="${NAABU_TOP_PORTS:-1000}"
NAABU_EXCLUDE="${NAABU_EXCLUDE:-22,23,3389}"
HTTP_TIMEOUT="${HTTP_TIMEOUT:-10}"
KATANA_DEPTH="${KATANA_DEPTH:-3}"
KATANA_FS="${KATANA_FS:-rdn}"
KATANA_HEADLESS="${KATANA_HEADLESS:-0}"

TS="$(date +%s)"
TARGET=""
FORCE=0
FRESH=0
SKIP_BRUTE=0
SKIP_PORTS=0
SKIP_HISTORY=0
SKIP_ARJUN=0
DB_ENABLED=1
PHASE_RC=0

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
  --file F              lê alvos de F (1 por linha, # comentário, wildcard ok)
  --skip-brute          pula shuffledns bruteforce
  --skip-ports          pula naabu (probe HTTP direto nos hostnames)
  --skip-history        pula waybackurls/gau
  --skip-arjun          pula descoberta de parâmetros ocultos
  -h, --help            esta ajuda

MULTI-TARGET
  Alvos são executados em sequência (1 por vez) para não saturar o alvo.
  A lista do menu fica em: ${TARGETS_FILE}
  Subdomínios cobertos por um alvo-pai da mesma lista são removidos (dedupe).

ENV
  THREADS MAX_PERMUTATIONS MAX_JS MAX_ARJUN NAABU_TOP_PORTS NAABU_EXCLUDE
  KATANA_DEPTH KATANA_FS KATANA_HEADLESS AUTH_FILE GH_TOKEN_FILE DB_PATH DOCS_ROOT
  TARGETS_FILE BANNER_FILE

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
  printf '\033[97m'
  if [[ -r "$BANNER_FILE" ]]; then
    cat "$BANNER_FILE"
  else
    printf '  recon_high_end v%s\n' "$VERSION"
  fi
  printf '\033[0m'
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
  [[ -s "$f" ]] || return 0
  cp -f "$f" "$LOGS/${tool}-${TS}.txt" 2>/dev/null || true
}

# ── Fases ────────────────────────────────────────────────────────────────────
run_phase() {
  local name="$1"; shift
  local t0=$SECONDS rc=0
  log "▶ FASE: ${name}"
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

# =============================================================================
#  FASE 1 — ASSET DISCOVERY
# =============================================================================
phase_asset() {
  local passive="$OUT/passive_raw.txt"
  : > "$passive"
  local d="$DOMAIN"

  if have subfinder; then
    timeout 900 subfinder -d "$d" -all -recursive -silent 2>>"$LOG" >> "$passive" \
      || warn "subfinder falhou"
  else
    warn "subfinder ausente"
  fi

  if have chaos; then
    timeout 600 chaos -d "$d" -silent 2>>"$LOG" >> "$passive" \
      || warn "chaos falhou (CHAOS_KEY configurada?)"
  fi

  # crt.sh — retry leve, falha é tolerável
  local crt
  crt="$(timeout 180 curl -s "https://crt.sh/?q=%25.${d}&output=json" 2>>"$LOG" || true)"
  if [[ -n "$crt" ]]; then
    printf '%s' "$crt" | jq -r '.[].name_value? // empty' 2>>"$LOG" >> "$passive" || true
  else
    warn "crt.sh sem resposta"
  fi

  if have github-subdomains; then
    local ghtoken="${GITHUB_TOKEN:-}"
    if [[ -z "$ghtoken" && -s "$GH_TOKEN_FILE" ]]; then
      ghtoken="$(head -n1 "$GH_TOKEN_FILE" 2>/dev/null | tr -d '\r\n ')"
    fi
    if [[ -n "$ghtoken" ]]; then
      timeout 600 github-subdomains -d "$d" -t "$ghtoken" -silent 2>>"$LOG" >> "$passive" \
        || warn "github-subdomains falhou"
    else
      warn "github-subdomains: sem token (env GITHUB_TOKEN ou ${GH_TOKEN_FILE}) — pulando"
    fi
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
  : > "$OUT/permutations.txt"
  if have alterx && have dnsx; then
    head -n "$MAX_PERMUTATIONS" "$OUT/subdomains_candidates.txt" \
      | timeout 900 alterx -silent 2>>"$LOG" \
      | sort -u | head -n "$MAX_PERMUTATIONS" \
      | timeout 1200 dnsx -silent -r "$RESOLVERS" 2>>"$LOG" \
      | sort -u > "$OUT/permutations.txt" || warn "alterx/dnsx falhou"
  else
    warn "alterx/dnsx ausentes: sem permutações"
  fi

  # Resolve tudo que é conhecido (fonte de verdade para portas/HTTP)
  sort -u "$OUT/subdomains_candidates.txt" "$OUT/permutations.txt" 2>/dev/null \
    | timeout 1800 dnsx -silent -r "$RESOLVERS" 2>>"$LOG" \
    | sort -u > "$OUT/subdomains.txt" || cp -f "$OUT/subdomains_candidates.txt" "$OUT/subdomains.txt"

  log "asset: $(count "$OUT/subdomains.txt") hosts resolvidos (passivo $(count "$OUT/passive.txt"), brute $(count "$OUT/brute.txt"), perm $(count "$OUT/permutations.txt"))"
  db_log asset subfinder ok "$OUT/subdomains.txt" "hosts=$(count "$OUT/subdomains.txt")" 0
  stamp "$OUT/subdomains.txt" subdomains
  stamp "$OUT/passive.txt" subfinder
}

phase_ports_http() {
  : > "$OUT/probe_targets.txt"

  if (( SKIP_PORTS )); then
    log "portas: pulado (--skip-ports)"
  elif have naabu; then
    log "portas: top ${NAABU_TOP_PORTS} (excluindo ${NAABU_EXCLUDE})"
    timeout 2400 naabu -list "$OUT/subdomains.txt" -top-ports "$NAABU_TOP_PORTS" \
      -ep "$NAABU_EXCLUDE" -silent -rate 1500 2>>"$LOG" \
      | sort -u > "$OUT/open_ports.txt" || warn "naabu falhou"
  else
    warn "naabu ausente"
  fi

  cat "$OUT/open_ports.txt" "$OUT/subdomains.txt" 2>/dev/null \
    | awk 'NF' | sort -u > "$OUT/probe_targets.txt" || true

  : > "$OUT/live.jsonl"
  local bin=""
  if have httpx-toolkit; then bin="httpx-toolkit"; elif have httpx; then bin="httpx"; fi
  if [[ -n "$bin" ]]; then
    log "probe HTTP via ${bin} em $(count "$OUT/probe_targets.txt") alvos"
    "$bin" -l "$OUT/probe_targets.txt" \
      -silent -json -title -sc -cl -td -server -location -fr -fc 404 \
      -timeout "$HTTP_TIMEOUT" -retries 1 -threads 50 -rl 150 \
      "${HDR_FLAGS[@]+"${HDR_FLAGS[@]}"}" \
      -o "$OUT/live.jsonl" 2>>"$LOG" || warn "httpx falhou parcialmente"
  else
    warn "httpx/httpx-toolkit ausentes: sem probe HTTP"
  fi

  if [[ -s "$OUT/live.jsonl" ]]; then
    jq -r 'select(.url != null) | .url' "$OUT/live.jsonl" 2>/dev/null | sort -u > "$OUT/live.txt" || true
  else
    : > "$OUT/live.txt"
  fi

  awk '{print $1}' "$OUT/live.txt" 2>/dev/null \
    | sed -E 's#^[a-z]+://##; s#[:/].*$##' | awk 'NF' | sort -u > "$OUT/live_hosts.txt" || true

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
        -o "$OUT/live_tls.jsonl" 2>>"$LOG" || warn "httpx (TLS) parcial"
      cat "$OUT/live_tls.jsonl" >> "$OUT/live.jsonl" 2>/dev/null || true
      jq -r 'select(.url != null) | .url' "$OUT/live.jsonl" 2>/dev/null | sort -u > "$OUT/live.txt" || true
      awk '{print $1}' "$OUT/live.txt" 2>/dev/null \
        | sed -E 's#^[a-z]+://##; s#[:/].*$##' | awk 'NF' | sort -u > "$OUT/live_hosts.txt" || true
    fi
  fi

  log "http: $(count "$OUT/live.txt") URLs vivas | portas: $(count "$OUT/open_ports.txt") | TLS novos: $(count "$OUT/tls_assets.txt")"
  db_log http httpx ok "$OUT/live.txt" "live=$(count "$OUT/live.txt") ports=$(count "$OUT/open_ports.txt")" 0
  stamp "$OUT/live.txt" httpx
  stamp "$OUT/open_ports.txt" naabu
  stamp "$OUT/tls_assets.txt" tlsx
}

# =============================================================================
#  FASE 2 — CONTENT DISCOVERY
# =============================================================================
phase_content() {
  : > "$OUT/urls_katana.txt"

  if have katana && [[ -s "$OUT/live.txt" ]]; then
    local extra=()
    (( KATANA_HEADLESS )) && extra+=(-hl -nos)
    log "katana: crawl (depth ${KATANA_DEPTH}, jsluice, auth=$([[ ${#HDRS[@]} -gt 0 ]] && echo sim || echo nao))"
    timeout 3600 katana -list "$OUT/live.txt" \
      -d "$KATANA_DEPTH" -jc -jsl -xhr -kf all -aff -fs "$KATANA_FS" \
      -rl 150 -c 10 -timeout "$HTTP_TIMEOUT" -silent \
      "${HDR_FLAGS[@]+"${HDR_FLAGS[@]}"}" "${extra[@]+"${extra[@]}"}" \
      -o "$OUT/urls_katana.txt" 2>>"$LOG" || warn "katana falhou parcialmente"
  else
    warn "katana ausente ou sem hosts vivos"
  fi

  : > "$OUT/urls_wayback.txt"; : > "$OUT/urls_gau.txt"
  if (( SKIP_HISTORY )); then
    log "histórico: pulado (--skip-history)"
  elif [[ -s "$OUT/live_hosts.txt" ]]; then
    if have waybackurls; then
      log "waybackurls: $(count "$OUT/live_hosts.txt") hosts (P=${THREADS})"
      xargs -r -P "$THREADS" -I{} bash -c 'timeout 300 waybackurls "$1" 2>/dev/null' _ {} \
        < "$OUT/live_hosts.txt" > "$OUT/urls_wayback.txt" || warn "waybackurls parcial"
    fi
    if have gau; then
      log "gau: $(count "$OUT/live_hosts.txt") hosts (P=${THREADS})"
      xargs -r -P "$THREADS" -I{} bash -c \
        'timeout 300 gau --threads 2 --blacklist png,jpg,jpeg,gif,svg,ico,woff,woff2,ttf,css,mp4,webp "$1" 2>/dev/null' _ {} \
        < "$OUT/live_hosts.txt" > "$OUT/urls_gau.txt" || warn "gau parcial"
    fi
  fi

  # Merge + dedup inteligente
  cat "$OUT/urls_katana.txt" "$OUT/urls_wayback.txt" "$OUT/urls_gau.txt" 2>/dev/null \
    | grep -E '^https?://' | sed -E 's/#.*$//' | awk 'NF' | sort -u > "$OUT/endpoints_crawl_raw.txt" || true

  if have uro && [[ -s "$OUT/endpoints_crawl_raw.txt" ]]; then
    uro -i "$OUT/endpoints_crawl_raw.txt" -o "$OUT/endpoints_crawl.txt" 2>>"$LOG" \
      || cp -f "$OUT/endpoints_crawl_raw.txt" "$OUT/endpoints_crawl.txt"
  else
    cp -f "$OUT/endpoints_crawl_raw.txt" "$OUT/endpoints_crawl.txt" 2>/dev/null || : > "$OUT/endpoints_crawl.txt"
  fi

  log "content: $(count "$OUT/endpoints_crawl.txt") endpoints (katana $(count "$OUT/urls_katana.txt") / wayback $(count "$OUT/urls_wayback.txt") / gau $(count "$OUT/urls_gau.txt"))"
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
      | xargs -0 -r jsluice secrets >> "$OUT/js_secrets.jsonl" 2>>"$LOG" || true

    if have trufflehog; then
      timeout 1800 trufflehog filesystem "$JS_DIR" --no-verification --json --no-update \
        >> "$OUT/js_secrets.jsonl" 2>>"$LOG" || warn "trufflehog parcial"
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
    awk '{print $1}' "$OUT/live.txt" 2>/dev/null \
      | grep -oE '^https?://[^/]+' | sort -u | head -n "$MAX_ARJUN" > "$OUT/arjun_targets.txt" || true
    log "arjun: $(count "$OUT/arjun_targets.txt") origins (P=5, parametros ocultos)"
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

  local kws="withdraw:12,transfer:12,payout:12,payment:10,checkout:10,wallet:10,redeem:10,admin:10,internal:10,apikey:10,api_key:10,kyc:10,bank:10,balance:8,invoice:8,billing:8,refund:8,transaction:8,coupon:8,subscription:8,order:8,profile:8,account:8,password:8,role:8,permission:8,graphql:8,webhook:8,oauth:8,jwt:8,iban:8,card:8,ssn:8,secret:8,credit:6,debit:6,manage:6,invite:6,api/v1:6,api/v2:6,api/v3:6,api/v4:6,user:6,reset:6,token:6,session:6,export:6,download:6,upload:6,import:6,delete:6,update:6,bulk:6,staff:6,sso:6,saml:6,mfa:6,2fa:6,verify:6,discount:6,plan:4,signup:4,register:4,callback:4"

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

## Números

| Artefato | Linhas |
|---|---|
| subdomains.txt | $(count "$OUT/subdomains.txt") |
| live.txt | $(count "$OUT/live.txt") |
| endpoints.txt | $(count "$OUT/endpoints.txt") |
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
  printf '\nPLANO — %d alvo(s) | threads=%s | fresh=%s | force=%s\n' \
    "${#TARGETS[@]}" "$THREADS" "$(onoff "$FRESH")" "$(onoff "$FORCE")"
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

settings_menu() {
  local opt val
  while true; do
    printf '\n  ── OPÇÕES ──────────────────────────────────\n'
    printf '   1) threads ......... %s\n' "$THREADS"
    printf '   2) skip-brute ...... %s\n' "$(onoff "$SKIP_BRUTE")"
    printf '   3) skip-ports ...... %s\n' "$(onoff "$SKIP_PORTS")"
    printf '   4) skip-history .... %s\n' "$(onoff "$SKIP_HISTORY")"
    printf '   5) skip-arjun ...... %s\n' "$(onoff "$SKIP_ARJUN")"
    printf '   6) fresh ........... %s\n' "$(onoff "$FRESH")"
    printf '   7) force (scope) ... %s\n' "$(onoff "$FORCE")"
    printf '   0) voltar\n'
    read -rp "  opção> " opt || return 0
    case "$opt" in
      1) read -rp "  threads [${THREADS}]: " val || continue
         if [[ "$val" =~ ^[0-9]+$ ]] && (( val > 0 )); then THREADS="$val"; else warn "valor inválido"; fi ;;
      2) SKIP_BRUTE=$((1 - SKIP_BRUTE)) ;;
      3) SKIP_PORTS=$((1 - SKIP_PORTS)) ;;
      4) SKIP_HISTORY=$((1 - SKIP_HISTORY)) ;;
      5) SKIP_ARJUN=$((1 - SKIP_ARJUN)) ;;
      6) FRESH=$((1 - FRESH)) ;;
      7) FORCE=$((1 - FORCE)) ;;
      0|"") return 0 ;;
      *) warn "opção inválida: ${opt}" ;;
    esac
  done
}

menu() {
  local opt line tok i
  while true; do
    printf '\n  %s── TARGETS (%d) ──%s\n' "$C_HDR" "${#TARGETS[@]}" "$C_RST"
    if (( ${#TARGETS[@]} == 0 )); then
      printf '   (lista vazia — use a opção 1)\n'
    else
      for i in "${!TARGETS[@]}"; do
        printf '   %2d) %s\n' "$((i + 1))" "${TARGETS[$i]}"
      done
    fi
    printf '\n   [1] adicionar   [2] importar arquivo   [3] remover   [4] limpar\n'
    printf '   [5] rodar TODOS [6] rodar selecionados  [7] opções    [0] sair\n'
    printf '   threads=%s brute=%s ports=%s history=%s arjun=%s fresh=%s force=%s\n' \
      "$THREADS" "$(onoff "$SKIP_BRUTE")" "$(onoff "$SKIP_PORTS")" \
      "$(onoff "$SKIP_HISTORY")" "$(onoff "$SKIP_ARJUN")" "$(onoff "$FRESH")" "$(onoff "$FORCE")"
    read -rp "  opção> " opt || return 0

    case "$opt" in
      1)
        read -rp "  targets (espaço/vírgula, aceita *.dominio): " line || continue
        line="${line//,/ }"
        for tok in $line; do add_target "$tok" || true; done
        save_targets_file
        ;;
      2)
        read -rp "  arquivo [${TARGETS_FILE}]: " line || continue
        line="${line:-$TARGETS_FILE}"
        load_targets_file "$line" || true
        save_targets_file
        ;;
      3)
        read -rp "  nº ou domínio para remover: " line || continue
        remove_target "$line" || true
        save_targets_file
        ;;
      4)
        read -rp "  limpar TODA a lista? (s/N): " line || continue
        if [[ "$line" =~ ^[sSyY]$ ]]; then
          TARGETS=(); save_targets_file; log "lista limpa"
        fi
        ;;
      5)
        if (( ${#TARGETS[@]} )); then
          run_batch "${TARGETS[@]}" || true
        else
          warn "lista vazia"
        fi
        save_targets_file
        ;;
      6)
        if (( ${#TARGETS[@]} == 0 )); then
          warn "lista vazia"; continue
        fi
        read -rp "  índices (ex: 1 3 4-6; vazio = todos): " line || continue
        if parse_selection "$line"; then
          run_batch "${SELECTED[@]}" || true
        fi
        ;;
      7) settings_menu ;;
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

  BATCH_ROWS+=("${TARGET}|ok|$(count "$OUT/subdomains.txt")|$(count "$OUT/live.txt")|$(count "$OUT/endpoints.txt")|$(count "$OUT/high_value_targets.txt")|$(count "$OUT/js_secrets.txt")")
  db_log batch "$TARGET" done "$OUT" \
    "subs=$(count "$OUT/subdomains.txt") live=$(count "$OUT/live.txt") hv=$(count "$OUT/high_value_targets.txt")" "$dur"
  [[ -n "${HV_AWK:-}" && -f "$HV_AWK" ]] && rm -f "$HV_AWK"
  return 0
}

write_batch_summary() {
  local dir="$1" ok="$2" fail="$3" skip="$4" row t st s l e h sec
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
  log "resumo: ${batch_dir}/SUMMARY.md"
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
  local positional=() files=() force_menu=0 plan=0 p f

  while (( $# )); do
    case "$1" in
      -h|--help) usage; exit 0 ;;
      --threads) THREADS="${2:?--threads exige valor}"; shift 2 ;;
      --fresh) FRESH=1; shift ;;
      --force) FORCE=1; shift ;;
      --plan) plan=1; shift ;;
      --menu) force_menu=1; shift ;;
      --file) files+=("${2:?--file exige caminho}"); shift 2 ;;
      --skip-brute) SKIP_BRUTE=1; shift ;;
      --skip-ports) SKIP_PORTS=1; shift ;;
      --skip-history) SKIP_HISTORY=1; shift ;;
      --skip-arjun) SKIP_ARJUN=1; shift ;;
      -*) die "flag desconhecida: $1 (use --help)" ;;
      *) positional+=("$1"); shift ;;
    esac
  done

  [[ "$THREADS" =~ ^[0-9]+$ ]] && (( THREADS > 0 )) || die "--threads inválido"

  print_banner

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
