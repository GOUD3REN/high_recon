# recon_high_end.sh — manual da ferramenta

> Versão documentada: **1.3.0**
> Local: `/home/hack/scripts/recon_high_end.sh`
> Banner: `/home/hack/scripts/banner.txt`

---

## 1. O que é

Pipeline de recon de alto padrão para bug bounty, feito para gerar **artefatos cirúrgicos** para validação manual (Caido/Playwright), e não scanning cego.

Filosofia:

- **Sem nuclei/dalfox em massa.** O script para no mapeamento; a validação é sua/do agente.
- **DB-first.** Cada fase grava no SQLite (`recon_logs`).
- **Paralelo, mas com teto de memória/tempo.** Chunks no katana, timeouts por ferramenta.
- **Foco em dinheiro.** O filtro final prioriza pagamento, auth, admin, API, PII.
- **Escopo é lei.** Nada roda fora do `targets/scope.md` sem `--force`.

O que ele **não** faz:

- Não valida vulnerabilidade (sem PoC, sem race, sem bypass).
- Não faz brute de diretórios/arquivos.
- Não contorna CAPTCHA/anti-bot.
- Não usa credenciais hardcoded.

---

## 2. Requisitos

Ferramentas usadas (todas opcionais com fallback, exceto `curl`/`jq`):

```
subfinder chaos crt.sh(curl) github-subdomains shuffledns alterx dnsx
naabu httpx-toolkit tlsx katana waybackurls gau urlscan(curl) uro
jsluice trufflehog arjun gf sqlite3 jq curl
```

Extras úteis: `tor` (histórico via SOCKS), `flock` (lock por alvo), `awk`.

Sem `tor`, o histórico depende de acesso direto ao Wayback/Common Crawl.

---

## 3. Início rápido

```bash
cd /home/hack

# menu interativo
./scripts/recon_high_end.sh

# um alvo direto
./scripts/recon_high_end.sh '*.nu.com.mx' --force --fresh

# vários alvos
./scripts/recon_high_end.sh '*.nu.com.mx' '*.nu.com.co' --force

# conferir sem fazer request
./scripts/recon_high_end.sh '*.nubank.com.br' --plan --force

# testar credenciais
./scripts/recon_high_end.sh --check-keys
```

O alvo aceita `https://`, caminho, vírgula, maiúsculas e wildcard:

```
*.example.com  → example.com
https://API.Example.com/x → api.example.com
```

---

## 4. Menu

```
╔══════════════════════════════════════════════════════════════════════════════╗
║ ☠  HACKBOT · RECON                                    « STRUGGLE »  v1.2.1 ║
║ 21:38 · /home/hack/docs · 3 alvo(s)        tema: berserk · perfil: default ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

### Ações

| Tecla | Ação |
|---|---|
| `1` / `a` | adicionar alvo(s) — espaço/vírgula, wildcard ok |
| `2` / `i` | importar lista de arquivo |
| `3` / `x` | remover por número ou domínio |
| `4` / `c` | limpar lista (pede confirmação) |
| `5` / `r` | rodar todos (sequencial) |
| `6` / `s` | rodar selecionados (`1 3 4-6`, vazio = todos) |
| `7` / `o` | opções |
| `8` / `p` | pastas em `docs/` (mostra caminho, estado e escopo) |
| `t` | trocar tema (`berserk` → `matrix` → `cyber` → `mono`) |
| `0` / `q` | sair |

A lista persiste em `/home/hack/targets/recon_targets.txt`.

### Tema

Salvo em `/home/hack/targets/recon_ui.conf` (chmod 600):

```
THEME=berserk
HISTORY_PROXY=auto
```

---

## 5. Perfis e opções (`[7]`)

### Perfis

| | default | `--deep` / `[7] 2` |
|---|---|---|
| ports | quick (top 100, `-ec`) | full (top 1000) |
| katana hosts | 120 | todos |
| katana chunk | 25 | 10 |
| depth | 3 | 3 |
| `-jsl` | off | off |
| `-aff` | off | off |
| escopo | fqdn | fqdn |
| bruteforce | off | on |
| permutações | 6.000 | 20.000 |
| JS baixados | 3.000 (+800 extra) | 6.000 (+1.500 extra) |
| arjun | 15 origins | 20 origins |
| subfinder max-time | 3 min | 8 min |
| teto URLs/chunk | 20.000 | 30.000 |
| timeout/chunk | 240s | 300s |

Qualquer ajuste manual vira **`custom`**. Alternar `[7] 2` aplica/restaura o preset.

### Itens do `[7]`

| # | Opção | Observação |
|---|---|---|
| 1 | threads | paralelismo global (default 10) |
| 2 | perfil DEEP | liga/desliga o preset |
| 3 | skip-brute | default **on** (brute off) |
| 4 | ports mode | `quick` → `full` → `none` |
| 5 | katana hosts | `0` = todos |
| 6 | katana depth | 1-10 |
| 7 | katana chunk | 5-200 hosts por processo |
| 8 | skip-history | pula wayback/gau/urlscan |
| 9 | skip-arjun | pula descoberta de parâmetros |
| 10 | skip-chaos | pula chaos |
| 11 | fresh | apaga `docs/<alvo>` antes |
| 12 | force | ignora `scope.md` |
| 13 | tema | berserk/matrix/cyber/mono |
| 14 | katana jsl | `-jsl` in-process (RAM!) |
| 15 | katana aff | auto form fill |
| 16 | katana escopo | `fqdn` (recomendado) ou `rdn` |
| 17 | katana fsu | colapsa URLs parecidas |
| 18 | teto/chunk | máx. URLs por chunk |
| 19 | katana headless | para SPA que só solta XHR no browser |
| 20 | history proxy | `auto` / `off` / `socks5h://host:porta` |

---

## 6. Fases

O lote roda **um alvo por vez**; dentro do alvo, as fases são:

```
[1/7] asset-discovery
[2/7] ports-http
[3/7] content
[4/7] js-analysis
[5/7] params
[6/7] high-value
[7/7] report
```

### 6.1 asset-discovery

1. Preflight de credenciais (GitHub e Chaos).
2. **chaos** (bulk, rápido).
3. **crt.sh** (valida JSON; retry 2x; rate limit é tolerado).
4. **github-subdomains** (token via env, nunca no argv).
5. **shuffledns** (só se brute ligado).
6. **alterx** → **dnsx** para permutações.
7. **subfinder** por último, com `-max-time`.
8. `dnsx` final resolve tudo (`-t 100`), com saída incremental em `.dnsx_final.txt`.

Saída: `passive.txt`, `brute.txt`, `permutations.txt`, `subdomains.txt`.

### 6.2 ports-http

- `naabu` conforme `PORTS_MODE`, com `-ec` (CDN só 80/443).
- `open_ports_raw.txt` cresce em tempo real.
- `host:80`/`host:443` são removidos da lista de probe (redundantes).
- `httpx` grava `live.jsonl` e deriva:
  - `live.txt` (normaliza `:443`/`:80`)
  - `live_clean.txt` (sem `400` de CDN)
  - `live_hosts.txt`
  - `crawl_targets.txt` (priorizado)
- `tlsx` coleta SAN/CN e adiciona assets novos.

Priorização do crawl (`crawl_targets.txt`):

```
+ fora de CDN
+ status 200 / 401 / 403
+ nome "de aplicação" (api, app, admin, auth, checkout, pay, graphql, staging...)
- blog, static, cdn, comunidade, help, careers...
```

### 6.3 content

- **wayback** via CDX (direto ou proxy) — um request, histórico de subdomínios.
- **gau** com providers (auto-pula se Common Crawl inacessível).
- **urlscan** API como fallback (3 páginas).
- **katana em chunks**, com memória controlada:
  - `-jc -xhr -kf all`, `-fs fqdn`, `-fsu`
  - `jsl`/`aff` opcionais
  - teto de URLs por chunk
  - detecção de OOM (`rc=137`) e de teto (`rc=141`)
  - guarda de memória livre (< 1.2 GB pula o chunk)
- Merge + `uro` → `endpoints_crawl.txt`.

Filtros aplicados: data-URI, base64, javascript:, mailto:, URLs > 2000 chars.

### 6.4 js-analysis

1. Seleciona `.js` de `endpoints_crawl.txt` (teto `MAX_JS`).
2. Baixa com UA de browser, `--compressed`, `-L` e Referer.
3. Registra falhas por status em `js/.failed.tsv`.
4. **2ª rodada**: baixa chunks `.js` descobertos dentro dos bundles.
5. `jsluice urls -R` por arquivo → `js_endpoints.jsonl`/`.txt`.
6. Sourcemaps: guarda `js_sources.txt` e só promove caminhos de API.
7. `jsluice secrets` + `trufflehog` → `js_secrets.jsonl`/`.txt`.
8. União com crawl → `endpoints.txt` (escopo de domínio).

### 6.5 params

- `gf` quando o pattern existe; senão fallback por regex:
  `params_xss`, `params_sqli`, `params_ssrf`, `params_redirect`, `params_idor`, `params_all`.
- `arjun` só em alvos:
  - `200` + `text/html`
  - não-CDN
  - resposta < 3s no probe
  - teto `MAX_ARJUN`
  - timeout por alvo (120s) e por fase (420s)
  - se o probe não achar nada: **pula a fase** (não insiste)
- Wordlist reduzida (`/home/hack/wordlists/params.txt`).

### 6.6 high-value

Pontua cada URL por palavras-chave (peso), ignora o nome do alvo (`nubank` ≠ `bank`) e gera:

- `high_value_targets_scored.tsv` (score, keywords, URL)
- `high_value_targets.txt` (top 500, ordenado)
- buckets: `hv_payments`, `hv_admin`, `hv_api`, `hv_auth`, `hv_data`
- `endpoints_params.txt` (com query)
- `endpoints_api.txt` (rotas `/api`, `/graphql`, `/vN`, `/bff`, `/admin`...)

Assets/sourcemap ficam fora do ranking.

### 6.7 report

Gera `SUMMARY.md` com:

- perfil usado
- contadores por artefato
- top 20 alvos de alto valor
- tamanho dos buckets
- próximos passos (Caido, loop adversarial, DB)

---

## 7. Artefatos

```
/home/hack/docs/<target>/
├── subdomains.txt             hosts resolvidos
├── passive.txt / brute.txt / permutations.txt
├── open_ports.txt             host:port
├── open_ports_raw.txt         saída incremental do naabu
├── live.txt / live_clean.txt / live_hosts.txt
├── live.jsonl                 saída do httpx
├── tls_assets.txt             hosts descobertos só no certificado
├── crawl_targets.txt          seeds priorizados do katana
├── urls_katana.txt / urls_wayback.txt / urls_gau.txt / urls_urlscan.txt
├── endpoints_crawl.txt        crawl+histórico dedup com uro
├── endpoints.txt              união final (crawl + JS), escopo do domínio
├── endpoints_params.txt       URLs com query
├── endpoints_api.txt          rotas de API
├── js_files.txt / js_files_extra.txt
├── js/                        bundles baixados, sourcemaps, .failed.tsv
├── js_endpoints.txt / .jsonl  rotas extraídas do JS
├── js_sources.txt             caminhos originais dos sourcemaps
├── js_secrets.txt / .jsonl    segredos (jsluice + trufflehog)
├── params_xss|sqli|ssrf|redirect|idor.txt
├── params_all.txt / arjun_params.txt
├── arjun/                     saída por origin
├── high_value_targets.txt
├── high_value_targets_scored.tsv
├── hv_payments.txt / hv_admin.txt / hv_api.txt / hv_auth.txt / hv_data.txt
├── SUMMARY.md
└── logs/
    ├── recon-<ts>.log
    ├── <tool>-<ts>.txt
    └── backup-<ts>/            artefatos anteriores movidos antes de sobrescrever
```

Credenciais de auth ficam em `/tmp/opencode/recon-curlrc-*` (chmod 400, removido no exit).

Lote:

```
/home/hack/docs/_batch-<ts>/SUMMARY.md
```

---

## 8. Credenciais e configuração

### Escopo

`/home/hack/targets/scope.md` — aceita domínio raiz ou wildcard. Fora dele:

- single-target: aborta;
- lote: marca `skip` e continua.

`--force` ignora (use só com autorização).

### Auth (cookies/headers)

`/home/hack/targets/auth_headers.txt`, uma header por linha:

```
Cookie: __Host-sessionid=...
Authorization: Bearer ...
```

- Usado por katana, httpx, arjun e download de JS.
- Nunca é gravado em `docs/`; o curl config fica em `/tmp/opencode` com `chmod 400` e é apagado no fim.

### GitHub

`/home/hack/targets/github_token` ou `GITHUB_TOKEN`.

- Passado por **env** (não aparece no `ps`).
- Validado contra `api.github.com/user` antes de usar.

### Chaos

Ordem: `CHAOS_KEY` → `/home/hack/targets/chaos_key` → `~/.config/chaos/config.yaml`.

- Validado com uma consulta real antes de usar.
- `SKIP_CHAOS=1` desliga.

### Histórico (Wayback)

```bash
HISTORY_PROXY=auto   # padrão: detecta Tor em 127.0.0.1:9050/9150
HISTORY_PROXY=off
HISTORY_PROXY=socks5h://127.0.0.1:9050
HISTORY_PROXY=http://user:pass@host:porta
```

O script usa **CDX via curl** (o `waybackurls` ignora proxy). Se o proxy não existir, tenta direto; se falhar, pula e usa urlscan.

---

## 9. Variáveis de ambiente

| Variável | Default | Efeito |
|---|---|---|
| `DOCS_ROOT` | `/home/hack/docs` | saída |
| `DB_PATH` | `opencode-pentester/db/findings.db` | SQLite |
| `THREADS` | 10 | paralelismo |
| `PORTS_MODE` | `quick` | `none/quick/full` |
| `NAABU_TOP_PORTS` | 1000 | usado no full |
| `NAABU_EXCLUDE` | `22,23,3389` | portas excluídas |
| `HTTP_TIMEOUT` | 8 | timeout HTTP |
| `MAX_PERMUTATIONS` | 6000 | permutações |
| `PERM_INPUT` | 1500 | input do alterx |
| `MAX_JS` | 3000 | downloads JS |
| `MAX_JS_EXTRA` | 800 | chunks da 2ª rodada |
| `MAX_ARJUN` | 15 | origins |
| `ARJUN_TIMEOUT` | 120 | por alvo |
| `ARJUN_PHASE_TIMEOUT` | 420 | fase |
| `ARJUN_FALLBACK` | 0 | usa crawl se probe=0 |
| `KATANA_MAX_HOSTS` | 120 | `0` = todos |
| `KATANA_CHUNK` | 25 | hosts/processo |
| `KATANA_DEPTH` | 3 | profundidade |
| `KATANA_FS` | `fqdn` | escopo |
| `KATANA_JSLUICE` | 0 | `-jsl` |
| `KATANA_AFF` | 0 | form fill |
| `KATANA_FSU` | 1 | filtra similares |
| `KATANA_HEADLESS` | 0 | browser |
| `KATANA_CHUNK_TIMEOUT` | 240 | por chunk |
| `KATANA_MAX_URLS_PER_CHUNK` | 20000 | teto por chunk |
| `CRAWL_EXCLUDE` | regex | hosts fora do crawl |
| `HISTORY_PROXY` | `auto` | proxy do CDX |
| `CDX_LIMIT` | 20000 | URLs do CDX |
| `URLSCAN_PAGES` | 3 | páginas urlscan |
| `GAU_PROVIDERS` | `commoncrawl,urlscan` | providers |
| `GAU_FORCE` | 0 | roda gau mesmo bloqueado |
| `SKIP_BRUTE` | 1 | pula brute |
| `SKIP_CHAOS` | 0 | pula chaos |
| `SUBFINDER_MAX_TIME` | 3 | minutos |
| `SCOPE_ENDPOINTS` | 1 | só URLs do alvo |
| `SCOPE_FILE` | `targets/scope.md` | escopo |
| `AUTH_FILE` | `targets/auth_headers.txt` | cookies/headers |
| `GH_TOKEN_FILE` | `targets/github_token` | token GitHub |
| `CHAOS_KEY_FILE` | `targets/chaos_key` | key do chaos |
| `TARGETS_FILE` | `targets/recon_targets.txt` | lista do menu |
| `BANNER_FILE` | `scripts/banner.txt` | ASCII do topo |
| `RESOLVERS` | `wordlists/resolvers/resolvers.txt` | DNS |
| `DNS_WORDLIST` | SecLists 110k | brute |
| `SUBFINDER_ALL` / `_RECURSIVE` | 0 | fontes extras (lento) |
| `SUBFINDER_MAX_TIME` | 3 | minutos |
| `SUBFINDER_TIMEOUT` | 10 | por request |
| `UA` | Chrome 129 | user-agent |
| `ARJUN_WORDLIST` | `wordlists/params.txt` | 6.4k params |

---

## 10. CLI

```
./scripts/recon_high_end.sh [alvos...] [opções]

--threads N
--fresh
--force
--plan
--check-keys
--file lista.txt
--skip-brute | --brute
--ports none|quick|full
--skip-ports
--skip-history
--skip-arjun
--skip-chaos
--deep
--katana-hosts N
--katana-depth N
--katana-chunk N
-V / --version
-h / --help
```

Precedência: a **última flag vence**. Ex.:

```bash
--deep --ports quick        # custom (quick)
--ports quick --deep        # DEEP (full)
```

---

## 11. Banco de dados

Tabela `recon_logs`:

```sql
CREATE TABLE IF NOT EXISTS recon_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  target TEXT, phase TEXT, tool TEXT, status TEXT,
  artifact TEXT, detail TEXT, duration_s INTEGER,
  created_at TEXT DEFAULT (datetime('now'))
);
```

Consultas úteis:

```bash
sqlite3 /home/hack/opencode-pentester/db/findings.db \
  "SELECT target,phase,status,detail,created_at FROM recon_logs ORDER BY id DESC LIMIT 20"
```

O batch grava uma linha com `target='__batch__'`.

---

## 12. Segurança operacional

### Snapshot imutável

No start, o script se copia para `/tmp/opencode/recon-run-<pid>.sh` e re-executa. Isso permite **editar o script durante uma run** sem quebrar a execução (bash lê scripts por offset).

### Lock por alvo

`flock` em `/tmp/opencode/recon-<alvo>.lock`.

- Impede duas runs no mesmo alvo (que já truncaram artefatos antes).
- Segundo processo: `já existe uma run ativa para <alvo> — pulando (lock)`.
- O arquivo pode sobrar em `/tmp`; o lock é do flock, não da existência do arquivo.

### Ctrl-C / SIGTERM

Há trap que:

1. loga `interrompido`;
2. encerra filhos (`pkill -TERM -P $$`);
3. sai com código 130.

Para parar à força:

```bash
pkill -TERM -f 'recon-run-'
pkill -TERM -f 'httpx-toolkit|naabu|katana|dnsx|subfinder|shuffledns|arjun'
```

### Segredos

- Cookies/tokens nunca vão para `docs/`.
- Token GitHub passado por env.
- Key do chaos por env ou arquivo lido, nunca no argv.
- `/tmp/opencode` é limpo no exit.

---

## 13. Limitações e troubleshooting

### `wayback: web.archive.org inacessível`

Seu IP/rede pode estar bloqueado no CDX. Verifique:

```bash
curl -s -o /dev/null -w '%{http_code}\n' https://web.archive.org/
```

- `000` = caminho bloqueado.
- Com Tor: `HISTORY_PROXY=auto` (padrão) detecta e usa.
- Common Crawl pode falhar mesmo via Tor (rejeita IP/CGNAT).

### `katana: chunk X/Y morto por OOM`

- Reduza `[7] 7` (chunk) para 5-10.
- Mantenha `[7] 14` (jsl) **off**.
- `[7] 15` (aff) off.
- Verifique memória: `grep MemAvailable /proc/meminfo`.

### `atingiu o teto de N URLs`

É o filtro funcionando. Ajuste `[7] 18` se quiser mais/menos.

### Blog/estático consumindo horas

Já excluído por `CRAWL_EXCLUDE`:

```
blog, static, cdn, comunidade, help, careers, forum, novidades...
```

Para adicionar: `CRAWL_EXCLUDE='...|meusite'`.

### `arjun: nenhum alvo responsivo`

Esperado em alvos 100% atrás de CDN/auth. A fase é pulada. Se quiser insistir: `ARJUN_FALLBACK=1`.

### `URL doesn't seem to be a webpage`

Não deve mais aparecer: arjun só recebe 200+HTML e a saída é silenciada.

### JS baixando pouco (403/404)

- `js: falhas por status: 404=.. 403=..` mostra o motivo.
- 404 = URLs históricas mortas.
- 403 = WAF/CDN; só com sessão/browser.

### Já existe uma run

Lock ativo. Aguarde ou:

```bash
pkill -TERM -f 'recon-run-'
```

### Nada aparece no terminal, mas o log cresce

Era um bug antigo (`exec ... 2>/dev/null`). Corrigido na 1.2.1. Se acontecer:

```bash
tail -f docs/<alvo>/logs/recon-*.log
```

### Terminal “morto”/Ctrl-C não responde

```bash
stty sane          # restaura intr/ixon
# Ctrl-Q destrava flow control (Ctrl-S)
```

Ou mate pelo PID mostrado no card de pré-voo.

---

## 14. Exemplos práticos

### Primeira passada rápida

```bash
./scripts/recon_high_end.sh '*.nu.com.mx' --force --fresh
```

### Deep em um alvo prioritário

```bash
./scripts/recon_high_end.sh '*.nubank.com.br' --force --fresh --deep
```

### Deep com histórico via Tor

```bash
HISTORY_PROXY=auto ./scripts/recon_high_end.sh '*.alvo.com' --force --fresh --deep
```

### SPA (só revela API no browser)

```bash
KATANA_HEADLESS=1 ./scripts/recon_high_end.sh '*.alvo.com' --force
```

### Sem naabu (probe direto em 80/443)

```bash
./scripts/recon_high_end.sh '*.alvo.com' --force --ports none
```

### Só validar alvos e perfil

```bash
./scripts/recon_high_end.sh '*.alvo.com' --plan --force
```

---

## 15. Changelog resumido

- **1.3.0** — `--version`; filtro de marca genérico (não depende mais de "nubank"); keywords `pay`/`pix`; reset completo do preset default; manual em `scripts/README-recon_high_end.md`.
- **1.2.1** — snapshot imutável (editar durante run), lock por alvo, trap Ctrl-C, fix de stderr no lock, CDX via proxy, logs de progresso no dnsx/naabu, filtros de data-URI/sourcemap, 2ª rodada de JS, arjun com probe/timeout, tema Berserk.
- **1.1.0** — multi-target, menu, dedupe, batch summary, silence do httpx, ports mode.
- **1.0.0** — pipeline inicial.

---

## 16. Onde mexer

| O quê | Onde |
|---|---|
| banner | `/home/hack/scripts/banner.txt` |
| tema/proxy | `/home/hack/targets/recon_ui.conf` |
| alvos | `/home/hack/targets/recon_targets.txt` |
| escopo | `/home/hack/targets/scope.md` |
| cookies | `/home/hack/targets/auth_headers.txt` |
| token GitHub | `/home/hack/targets/github_token` |
| key chaos | `/home/hack/targets/chaos_key` |
| wordlists | `/home/hack/wordlists/` |
| resumo por alvo | `docs/<alvo>/SUMMARY.md` |
| resumo do lote | `docs/_batch-<ts>/SUMMARY.md` |
