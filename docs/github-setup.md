# Configuração do repositório no GitHub

Passo a passo para publicar o repositório e ligar os gates. A ordem importa: um status
check só aparece para ser marcado como obrigatório depois de rodar ao menos uma vez.

## 1. Criar o repositório privado e dar acesso ao professor

1. GitHub → **New repository** → nome `taskflow-devsecops` → **Private** → sem README.
2. **Settings → Collaborators → Add people** → `HardSource` com permissão **Read**.
3. Adicione [@jessicacamarco](https://github.com/jessicacamarco) e
   [@diegotavares16](https://github.com/diegotavares16) com permissão **Write**
   (o CODEOWNERS só vale para quem tem Write).

> **Branch protection em repositório privado** exige GitHub **Pro** (conta pessoal) ou
> **Team** (organização). Estudantes têm o Pro grátis pelo
> [GitHub Student Developer Pack](https://education.github.com/pack). Sem isso, a tela
> de proteção avisa que as regras "não serão aplicadas".

## 2. Publicar a linha de base e as branches

```bash
git remote add origin git@github.com:weynne/taskflow-devsecops.git
git push -u origin main                    # só o commit da linha de base vulnerável
git push -u origin feat/ci-base feat/sast feat/sca feat/container-hardening docs/entrega
```

## 3. CODEOWNERS

Já preenchido com o grupo WJD. Toda regra tem dois donos, então o autor do PR nunca é o
único revisor possível. Os donos precisam ter aceitado o convite de collaborator com
**Write**, ou o GitHub ignora a regra.

O arquivo fica versionado desde o PR 1. Enquanto **"Require review from Code Owners"**
estiver desligado (fase de construção, seção 5), o GitHub só **sugere** os donos como
revisores, sem bloquear o merge.

## 4. Abrir os PRs na ordem (cada um contra a `main`)

| PR | Branch | O que entra | Checks que aparecem |
| --- | --- | --- | --- |
| 1 | `feat/ci-base` | ruff, action composta, `ci.yml`, CODEOWNERS | `Build e lint (ruff)` |
| 2 | `feat/sast` | `sast.yml`, `.gitleaks.toml`, correções do `app.py`, testes | + `Testes (pytest)`, `SAST - Semgrep`, `Secret Scanning - Gitleaks` |
| 3 | `feat/sca` | requirements com hashes, `sca.yml`, Dependabot | + `SCA - pip-audit`, `SCA - Trivy fs` |
| 4 | `feat/container-hardening` | Dockerfile, script de runtime, `container.yml` | + `Imagem - build, Trivy e smoke test` |
| 5 | `docs/entrega` | README e `docs/` | — |

Cada branch foi criada a partir da anterior. Depois de mergear o PR *N*, o PR *N+1* passa a
mostrar só o próprio diff. Use **"Create a merge commit"** para preservar os commits
pequenos no histórico.

Na fase de construção, quem monta o repositório abre e mergeia os PRs sozinho, assim que os
checks ficam verdes. Se a Jéssica ou o Diego puderem, um comentário ou uma aprovação em algum
PR ajuda a evidenciar a participação (Seção 5 das Rubricas Gerais), mas não é pré-requisito
para o merge.

## 5. Branch protection da `main`

A proteção é ligada em duas fases. Os **gates automáticos valem desde o início**: nenhum PR
com check vermelho entra na `main`. Só a **revisão humana obrigatória** fica para o final,
para a montagem não depender da disponibilidade dos colegas.

### Fase 1 — construção (logo após o PR 1)

**Settings → Branches → Add classic branch protection rule** → Branch name pattern: `main`

- [x] **Require a pull request before merging**
  - [ ] Require approvals: **desmarcado** (por enquanto)
  - [ ] Require review from Code Owners: **desmarcado** (por enquanto)
- [x] **Require status checks to pass before merging**
  - [x] Require branches to be up to date before merging
  - Checks obrigatórios (adicione cada um assim que aparecer pela primeira vez):
    - `Build e lint (ruff)`
    - `Testes (pytest)`
    - `SAST - Semgrep`
    - `Secret Scanning - Gitleaks`
    - `SCA - pip-audit`
    - `SCA - Trivy fs`
    - `Imagem - build, Trivy e smoke test`
- [x] **Do not allow bypassing the above settings** (vale também para administradores)
- [ ] Allow force pushes / Allow deletions: **desmarcados**

Volte a esta tela depois dos PRs 2, 3 e 4 para marcar os checks novos.

Nesta fase o push direto na `main` continua bloqueado (só entra via PR) e um gate vermelho
continua impedindo o merge. A única diferença é que o PR verde pode ser mergeado sem aprovação.

### Fase 2 — entrega (depois do PR 5, antes de enviar ao professor)

Edite a mesma regra e marque:

- [x] Require approvals: **1**
- [x] Dismiss stale pull request approvals when new commits are pushed
- [x] **Require review from Code Owners**

A rubrica avalia "`main` protegida com *required checks* e `CODEOWNERS`", e o professor
consulta o repositório depois da aula. Por isso, ligue a fase 2 **antes de enviar a entrega**
e mantenha ligada. A partir daqui, o PR da demonstração precisa da aprovação da Jéssica ou do
Diego para ser mergeado, mesmo com todos os checks verdes. Essa é a parte "humana" do
portão, e dá para mostrá-la ao vivo.

## 6. Dependabot e segurança do repositório

**Settings → Code security**: habilite **Dependency graph**, **Dependabot alerts** e
**Dependabot security updates**. O `.github/dependabot.yml` já cuida das atualizações de
versão (pip, actions e docker).

## 7. Evidências para a entrega

- Aba **Actions**: um run verde de cada workflow na `main` (copie os links para o README).
- PR de demonstração do shift-left com o gate vermelho e o merge bloqueado
  ([roteiro](apresentacao.md)).
- Print da tela de branch protection **já na fase 2** (aprovação + Code Owners ligados).
