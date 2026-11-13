# Relatório do Agente de Segurança

- **Projeto:** `app-vulneravel`
- **Gerado em:** 28/10/2026, 16:53:37
- **Gatilho:** sob-demanda · **Modo:** completo
- **Stack detectada:** node, express, mysql
- **Arquivos analisados:** 7 · **Análise contextual (LLM):** não · **Duração:** 0.0s

> ℹ️ Este relatório é **consultivo**: o agente não bloqueia commits, pushes ou merges. Todas as vulnerabilidades — inclusive as de risco baixo — devem ser registradas e corrigidas.

## Resumo

| Severidade | Quantidade |
|---|---|
| 🔴 Crítico | 5 |
| 🟠 Alto | 10 |
| 🟡 Médio | 9 |
| 🔵 Baixo | 4 |
| **Total** | **28** |

## Vulnerabilidades

### 1. 🔴 Arquivo .env versionado no repositório

| Campo | Valor |
|---|---|
| **Vulnerabilidade** | Arquivo .env versionado no repositório (`SEG-006`) |
| **Arquivo/linha** | `.env:1` |
| **Nível de risco** | 🔴 **Crítico** |
| **Categoria** | Credenciais/Segredos |
| **OWASP** | A07:2021 – Identification and Authentication Failures / A02:2021 – Cryptographic Failures |
| **Origem / confiança** | regra / alta |

**Trecho:**
```bash
2 variável(is) com valor definido
```
**Explicação:** Um arquivo .env com variáveis de ambiente reais está sendo rastreado pelo Git.

**Impacto:** Qualquer pessoa com acesso ao repositório (ou ao histórico do Git) obtém a credencial e pode acessar o recurso protegido: banco de dados, APIs pagas ou contas de terceiros.

**Recomendação:** Execute `git rm --cached <arquivo>`, adicione `.env*` ao .gitignore (mantendo apenas um `.env.example` sem valores reais) e troque todas as credenciais que estavam no arquivo.

**Exemplo de correção:**
```bash
# .gitignore
.env
.env.*
!.env.example

# .env.example (versionado, sem valores reais)
DB_PASSWORD=
JWT_SECRET=
```

### 2. 🔴 String de conexão com usuário e senha embutidos

| Campo | Valor |
|---|---|
| **Vulnerabilidade** | String de conexão com usuário e senha embutidos (`SEG-003`) |
| **Arquivo/linha** | `src/db/conexao.ts:11` |
| **Nível de risco** | 🔴 **Crítico** |
| **Categoria** | Credenciais/Segredos |
| **OWASP** | A07:2021 – Identification and Authentication Failures / A02:2021 – Cryptographic Failures |
| **Origem / confiança** | regra / alta |

**Trecho:**
```ts
export const urlBackup = 'mysql://admin:Su********@db.interno:3306/escola';
```
**Explicação:** A URL de conexão com o banco/serviço contém a senha em texto puro.

**Impacto:** Qualquer pessoa com acesso ao repositório (ou ao histórico do Git) obtém a credencial e pode acessar o recurso protegido: banco de dados, APIs pagas ou contas de terceiros.

**Recomendação:** Remova o valor do código, mova-o para uma variável de ambiente (.env fora do versionamento ou cofre de segredos) e REVOGUE/troque a credencial exposta, pois ela continua no histórico do Git.

**Exemplo de correção:**
```ts
const conexao = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});
```

### 3. 🔴 Entrada do usuário inserida diretamente na consulta SQL

| Campo | Valor |
|---|---|
| **Vulnerabilidade** | Entrada do usuário inserida diretamente na consulta SQL (`SQL-002`) |
| **Arquivo/linha** | `src/routes/alunos.ts:18` |
| **Nível de risco** | 🔴 **Crítico** |
| **Categoria** | SQL Injection |
| **OWASP** | A03:2021 – Injection |
| **Origem / confiança** | regra / alta |

**Trecho:**
```ts
await pool.query('DELETE FROM alunos WHERE id = ' + req.params.id);
```
**Explicação:** Dados vindos da requisição (req.body, req.query, req.params, $_GET, request.args...) são colocados diretamente no texto da consulta SQL.

**Impacto:** Um atacante pode alterar a consulta SQL enviada ao banco: ler dados de outros usuários (notas, faltas, dados pessoais), contornar o login, alterar ou apagar registros.

**Recomendação:** Nunca monte SQL com interpolação/concatenação de valores. Use consultas parametrizadas (placeholders ? ou :nome) ou os métodos seguros do ORM/query builder. Para nomes de colunas/ordenação dinâmicos, use uma lista de valores permitidos (allowlist).

**Exemplo de correção:**
```ts
// mysql2 — consulta parametrizada (prepared statement)
const [linhas] = await pool.execute(
  'SELECT * FROM usuarios WHERE email = ? AND ativo = ?',
  [email, true],
);
```

### 4. 🔴 Rota administrativa sem autenticação: PUT /admin/config

| Campo | Valor |
|---|---|
| **Vulnerabilidade** | Rota administrativa sem autenticação: PUT /admin/config (`AUZ-003`) |
| **Arquivo/linha** | `src/routes/alunos.ts:22` |
| **Nível de risco** | 🔴 **Crítico** |
| **Categoria** | Autorização |
| **OWASP** | A01:2021 – Broken Access Control |
| **Origem / confiança** | regra / media |

**Trecho:**
```ts
router.put('/admin/config', async (req, res) => {
```
**Explicação:** Uma rota cujo caminho indica função administrativa foi declarada sem middleware de autenticação/autorização.

**Impacto:** Usuários não autenticados (ou sem o perfil adequado) podem acessar ou alterar dados e funcionalidades restritas.

**Recomendação:** Proteja a rota com middleware de autenticação e, quando aplicável, de autorização por perfil (ex.: admin, professor, aluno). Se a rota for propositalmente pública, documente com o comentário "seguranca-ignore".

**Exemplo de correção:**
```ts
// middleware de autenticação + autorização por perfil
export function autenticar(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ erro: 'Não autenticado' });
  try {
    req.usuario = jwt.verify(token, process.env.JWT_SECRET!, { algorithms: ['HS256'] });
    next();
  } catch {
    return res.status(401).json({ erro: 'Token inválido' });
  }
}

export const exigirPerfil = (...perfis: string[]) => (req, res, next) =>
  perfis.includes(req.usuario?.perfil) ? next() : res.status(403).json({ erro: 'Acesso negado' });

router.delete('/alunos/:id', autenticar, exigirPerfil('admin'), excluirAluno);
```

### 5. 🔴 Entrada do usuário inserida diretamente na consulta SQL

| Campo | Valor |
|---|---|
| **Vulnerabilidade** | Entrada do usuário inserida diretamente na consulta SQL (`SQL-002`) |
| **Arquivo/linha** | `src/routes/auth.ts:11` |
| **Nível de risco** | 🔴 **Crítico** |
| **Categoria** | SQL Injection |
| **OWASP** | A03:2021 – Injection |
| **Origem / confiança** | regra / alta |

**Trecho:**
```ts
const [linhas]: any = await pool.query(`SELECT * FROM usuarios WHERE email = '${req.body.email}'`);
```
**Explicação:** Dados vindos da requisição (req.body, req.query, req.params, $_GET, request.args...) são colocados diretamente no texto da consulta SQL.

**Impacto:** Um atacante pode alterar a consulta SQL enviada ao banco: ler dados de outros usuários (notas, faltas, dados pessoais), contornar o login, alterar ou apagar registros.

**Recomendação:** Nunca monte SQL com interpolação/concatenação de valores. Use consultas parametrizadas (placeholders ? ou :nome) ou os métodos seguros do ORM/query builder. Para nomes de colunas/ordenação dinâmicos, use uma lista de valores permitidos (allowlist).

**Exemplo de correção:**
```ts
// mysql2 — consulta parametrizada (prepared statement)
const [linhas] = await pool.execute(
  'SELECT * FROM usuarios WHERE email = ? AND ativo = ?',
  [email, true],
);
```

### 6. 🟠 Coluna de senha com tamanho incompatível com hash seguro

| Campo | Valor |
|---|---|
| **Vulnerabilidade** | Coluna de senha com tamanho incompatível com hash seguro (`BD-001`) |
| **Arquivo/linha** | `database/schema.sql:4` |
| **Nível de risco** | 🟠 **Alto** |
| **Categoria** | Banco de Dados |
| **OWASP** | A02:2021 – Cryptographic Failures |
| **Origem / confiança** | regra / media |

**Trecho:**
```sql
senha VARCHAR(32) NOT NULL,
```
**Explicação:** A coluna de senha tem menos de 60 caracteres — tamanho mínimo de um hash bcrypt. Isso indica armazenamento em texto puro ou com hash fraco.

**Impacto:** Se o banco vazar, as senhas de alunos, professores e administradores ficam expostas e podem ser reutilizadas em outros serviços.

**Recomendação:** Armazene apenas o hash (bcrypt/Argon2) em uma coluna de pelo menos VARCHAR(255) e nunca a senha original.

**Exemplo de correção:**
```sql
ALTER TABLE usuarios
  CHANGE COLUMN senha senha_hash VARCHAR(255) NOT NULL;
```

### 7. 🟠 Senha de usuário do banco escrita no script SQL

| Campo | Valor |
|---|---|
| **Vulnerabilidade** | Senha de usuário do banco escrita no script SQL (`BD-003`) |
| **Arquivo/linha** | `database/schema.sql:16` |
| **Nível de risco** | 🟠 **Alto** |
| **Categoria** | Credenciais/Segredos |
| **OWASP** | A07:2021 – Identification and Authentication Failures |
| **Origem / confiança** | regra / alta |

**Trecho:**
```sql
CREATE USER 'app'@'%' IDENTIFIED BY 'ap****';
```
**Explicação:** CREATE USER / ALTER USER / SET PASSWORD contém a senha literal no arquivo versionado.

**Impacto:** Qualquer pessoa com acesso ao repositório conhece a senha do usuário do banco.

**Recomendação:** Remova a senha do script; gere-a no momento do provisionamento a partir de uma variável de ambiente ou cofre de segredos.

**Exemplo de correção:**
```sql
-- provisionamento (shell), senha vinda do ambiente:
-- mysql -e "CREATE USER 'app'@'%' IDENTIFIED BY '$DB_APP_PASSWORD';"
```

### 8. 🟠 Privilégios excessivos concedidos no banco de dados

| Campo | Valor |
|---|---|
| **Vulnerabilidade** | Privilégios excessivos concedidos no banco de dados (`BD-002`) |
| **Arquivo/linha** | `database/schema.sql:17` |
| **Nível de risco** | 🟠 **Alto** |
| **Categoria** | Banco de Dados |
| **OWASP** | A01:2021 – Broken Access Control |
| **Origem / confiança** | regra / alta |

**Trecho:**
```sql
GRANT ALL PRIVILEGES ON *.* TO 'app'@'%';
```
**Explicação:** O script concede ALL PRIVILEGES e/ou libera o acesso a partir de qualquer host ("%").

**Impacto:** Se a aplicação for comprometida (ex.: via SQL Injection), o atacante herda privilégios totais: apagar tabelas, criar usuários, ler outros bancos.

**Recomendação:** Crie um usuário específico da aplicação com o mínimo necessário (SELECT, INSERT, UPDATE, DELETE no schema da aplicação) e restrito ao host do backend.

**Exemplo de correção:**
```sql
CREATE USER 'app_escola'@'10.0.0.%' IDENTIFIED BY '<definida no cofre de segredos>';
GRANT SELECT, INSERT, UPDATE, DELETE ON escola.* TO 'app_escola'@'10.0.0.%';
```

### 9. 🟠 Senha, segredo ou chave de API escrito diretamente no código

| Campo | Valor |
|---|---|
| **Vulnerabilidade** | Senha, segredo ou chave de API escrito diretamente no código (`SEG-004`) |
| **Arquivo/linha** | `src/db/conexao.ts:6` |
| **Nível de risco** | 🟠 **Alto** |
| **Categoria** | Credenciais/Segredos |
| **OWASP** | A07:2021 – Identification and Authentication Failures / A02:2021 – Cryptographic Failures |
| **Origem / confiança** | regra / media |

**Trecho:**
```ts
password: 'ro*****',
```
**Explicação:** Uma variável/propriedade com nome de credencial recebe um valor literal fixo.

**Impacto:** Qualquer pessoa com acesso ao repositório (ou ao histórico do Git) obtém a credencial e pode acessar o recurso protegido: banco de dados, APIs pagas ou contas de terceiros.

**Recomendação:** Remova o valor do código, mova-o para uma variável de ambiente (.env fora do versionamento ou cofre de segredos) e REVOGUE/troque a credencial exposta, pois ela continua no histórico do Git.

**Exemplo de correção:**
```ts
// .env (NÃO versionar — adicione ao .gitignore)
// DB_PASSWORD=...

// código
const senhaBanco = process.env.DB_PASSWORD;
if (!senhaBanco) throw new Error('DB_PASSWORD não configurada');
```

### 10. 🟠 Rota que altera dados sem middleware de autenticação: DELETE /:id

| Campo | Valor |
|---|---|
| **Vulnerabilidade** | Rota que altera dados sem middleware de autenticação: DELETE /:id (`AUZ-001`) |
| **Arquivo/linha** | `src/routes/alunos.ts:17` |
| **Nível de risco** | 🟠 **Alto** |
| **Categoria** | Autorização |
| **OWASP** | A01:2021 – Broken Access Control |
| **Origem / confiança** | regra / media |

**Trecho:**
```ts
router.delete('/:id', async (req, res) => {
```
**Explicação:** Uma rota POST/PUT/PATCH/DELETE foi declarada sem nenhum middleware de autenticação/autorização identificável.

**Impacto:** Usuários não autenticados (ou sem o perfil adequado) podem acessar ou alterar dados e funcionalidades restritas.

**Recomendação:** Proteja a rota com middleware de autenticação e, quando aplicável, de autorização por perfil (ex.: admin, professor, aluno). Se a rota for propositalmente pública, documente com o comentário "seguranca-ignore".

**Exemplo de correção:**
```ts
// middleware de autenticação + autorização por perfil
export function autenticar(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ erro: 'Não autenticado' });
  try {
    req.usuario = jwt.verify(token, process.env.JWT_SECRET!, { algorithms: ['HS256'] });
    next();
  } catch {
    return res.status(401).json({ erro: 'Token inválido' });
  }
}

export const exigirPerfil = (...perfis: string[]) => (req, res, next) =>
  perfis.includes(req.usuario?.perfil) ? next() : res.status(403).json({ erro: 'Acesso negado' });

router.delete('/alunos/:id', autenticar, exigirPerfil('admin'), excluirAluno);
```

### 11. 🟠 Caminho de arquivo controlado pelo usuário (Path Traversal)

| Campo | Valor |
|---|---|
| **Vulnerabilidade** | Caminho de arquivo controlado pelo usuário (Path Traversal) (`ENT-003`) |
| **Arquivo/linha** | `src/routes/alunos.ts:28` |
| **Nível de risco** | 🟠 **Alto** |
| **Categoria** | Validação de Entrada |
| **OWASP** | A01:2021 – Broken Access Control |
| **Origem / confiança** | regra / media |

**Trecho:**
```ts
res.sendFile('/var/boletins/' + req.params.arquivo);
```
**Explicação:** Um caminho de arquivo é montado a partir de dados da requisição sem normalização/validação.

**Impacto:** Com valores como "../../.env", o atacante lê ou sobrescreve arquivos fora do diretório permitido.

**Recomendação:** Resolva o caminho com path.resolve e confirme que ele continua dentro do diretório base; prefira identificadores em vez de nomes de arquivo.

**Exemplo de correção:**
```ts
import path from 'node:path';
const BASE = path.resolve('uploads');
const destino = path.resolve(BASE, String(req.params.nome));
if (!destino.startsWith(BASE + path.sep)) return res.status(400).json({ erro: 'Caminho inválido' });
res.sendFile(destino);
```

### 12. 🟠 Segredo com valor padrão fixo quando a variável de ambiente não existe

| Campo | Valor |
|---|---|
| **Vulnerabilidade** | Segredo com valor padrão fixo quando a variável de ambiente não existe (`SEG-005`) |
| **Arquivo/linha** | `src/routes/auth.ts:7` |
| **Nível de risco** | 🟠 **Alto** |
| **Categoria** | Credenciais/Segredos |
| **OWASP** | A07:2021 – Identification and Authentication Failures / A02:2021 – Cryptographic Failures |
| **Origem / confiança** | regra / alta |

**Trecho:**
```ts
const JWT_SECRET = process.env.JWT_SECRET || 'se********';
```
**Explicação:** O código lê o segredo de process.env, mas usa um valor literal como alternativa (|| ou ??). Se a variável não for configurada em produção, o sistema roda com um segredo conhecido publicamente.

**Impacto:** Com um JWT_SECRET/SESSION_SECRET previsível, um atacante consegue forjar tokens e se autenticar como qualquer usuário, inclusive administradores.

**Recomendação:** Remova o valor padrão e faça a aplicação falhar na inicialização se o segredo não estiver definido.

**Exemplo de correção:**
```ts
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) throw new Error('JWT_SECRET não configurado');
```

### 13. 🟠 Senha comparada diretamente (provável armazenamento em texto puro)

| Campo | Valor |
|---|---|
| **Vulnerabilidade** | Senha comparada diretamente (provável armazenamento em texto puro) (`AUT-003`) |
| **Arquivo/linha** | `src/routes/auth.ts:13` |
| **Nível de risco** | 🟠 **Alto** |
| **Categoria** | Autenticação |
| **OWASP** | A02:2021 – Cryptographic Failures |
| **Origem / confiança** | regra / media |

**Trecho:**
```ts
if (!usuario || usuario.senha !== senha) return res.status(401).json({ erro: 'inválido' });
```
**Explicação:** A senha informada é comparada com ===/== em vez de uma função de verificação de hash.

**Impacto:** Indica que as senhas estão salvas sem hash; um vazamento do banco expõe a senha de todos os usuários. A comparação direta também é sujeita a ataques de tempo.

**Recomendação:** Armazene apenas o hash da senha e verifique com bcrypt.compare / argon2.verify.

**Exemplo de correção:**
```ts
const usuario = await buscarPorEmail(email);
const ok = usuario && (await bcrypt.compare(senha, usuario.senhaHash));
if (!ok) return res.status(401).json({ erro: 'Credenciais inválidas' });
```

### 14. 🟠 Algoritmo de hash inadequado para senhas (MD5/SHA-1/SHA-256 simples)

| Campo | Valor |
|---|---|
| **Vulnerabilidade** | Algoritmo de hash inadequado para senhas (MD5/SHA-1/SHA-256 simples) (`AUT-001`) |
| **Arquivo/linha** | `src/routes/auth.ts:20` |
| **Nível de risco** | 🟠 **Alto** |
| **Categoria** | Autenticação |
| **OWASP** | A02:2021 – Cryptographic Failures |
| **Origem / confiança** | regra / media |

**Trecho:**
```ts
const hash = crypto.createHash('md5').update(req.body.senha).digest('hex');
```
**Explicação:** Foi identificado um hash rápido (MD5, SHA-1 ou SHA-256 sem fator de custo) em código que lida com senhas.

**Impacto:** Em caso de vazamento do banco, as senhas podem ser quebradas em minutos por força bruta ou tabelas pré-computadas.

**Recomendação:** Use um algoritmo próprio para senhas, com salt e fator de custo: bcrypt (custo ≥ 10), scrypt ou Argon2id.

**Exemplo de correção:**
```ts
import bcrypt from 'bcrypt';
const hash = await bcrypt.hash(senha, 12);          // ao cadastrar
const confere = await bcrypt.compare(senha, hash);  // ao autenticar
```

### 15. 🟠 Perfil/permissão do usuário obtido de dados enviados pelo cliente

| Campo | Valor |
|---|---|
| **Vulnerabilidade** | Perfil/permissão do usuário obtido de dados enviados pelo cliente (`PER-001`) |
| **Arquivo/linha** | `src/routes/auth.ts:21` |
| **Nível de risco** | 🟠 **Alto** |
| **Categoria** | Permissões |
| **OWASP** | A01:2021 – Broken Access Control |
| **Origem / confiança** | regra / media |

**Trecho:**
```ts
await pool.query('INSERT INTO usuarios (email, senha, perfil) VALUES (?, ?, ?)', [req.body.email, hash, req.body.perfil]);
```
**Explicação:** O perfil ou nível de acesso (role, perfil, isAdmin, tipo...) é lido de req.body/query/headers/params, ou seja, de um valor que o próprio usuário controla.

**Impacto:** Escalonamento de privilégio: um aluno pode enviar "perfil": "admin" e obter acesso administrativo.

**Recomendação:** Obtenha o perfil sempre de uma fonte confiável no servidor (token verificado ou banco de dados). Se um administrador puder definir perfis, valide o perfil de quem faz a requisição e restrinja os valores a uma lista permitida.

**Exemplo de correção:**
```ts
// perfil vem do token verificado pelo middleware, nunca do corpo da requisição
const perfil = req.usuario.perfil;
if (perfil !== 'admin') return res.status(403).json({ erro: 'Acesso negado' });
```

### 16. 🟡 Execução de múltiplas instruções SQL habilitada

| Campo | Valor |
|---|---|
| **Vulnerabilidade** | Execução de múltiplas instruções SQL habilitada (`SQL-004`) |
| **Arquivo/linha** | `src/db/conexao.ts:8` |
| **Nível de risco** | 🟡 **Médio** |
| **Categoria** | SQL Injection |
| **OWASP** | A03:2021 – Injection |
| **Origem / confiança** | regra / alta |

**Trecho:**
```ts
multipleStatements: true,
```
**Explicação:** A opção multipleStatements permite que uma única chamada execute várias instruções separadas por ponto e vírgula.

**Impacto:** Se existir qualquer ponto de injeção, o atacante pode encadear comandos destrutivos (ex.: DROP TABLE) na mesma chamada.

**Recomendação:** Desabilite multipleStatements, a menos que seja estritamente necessário e restrito a scripts internos.

**Exemplo de correção:**
```ts
const pool = mysql.createPool({
  // ...
  multipleStatements: false,
});
```

### 17. 🟡 Rota de consulta sem middleware de autenticação: GET /

| Campo | Valor |
|---|---|
| **Vulnerabilidade** | Rota de consulta sem middleware de autenticação: GET / (`AUZ-002`) |
| **Arquivo/linha** | `src/routes/alunos.ts:7` |
| **Nível de risco** | 🟡 **Médio** |
| **Categoria** | Autorização |
| **OWASP** | A01:2021 – Broken Access Control |
| **Origem / confiança** | regra / media |

**Trecho:**
```ts
router.get('/', async (_req, res) => {
```
**Explicação:** Uma rota GET foi declarada sem middleware de autenticação identificável; ela pode expor dados a qualquer pessoa.

**Impacto:** Usuários não autenticados (ou sem o perfil adequado) podem acessar ou alterar dados e funcionalidades restritas.

**Recomendação:** Proteja a rota com middleware de autenticação e, quando aplicável, de autorização por perfil (ex.: admin, professor, aluno). Se a rota for propositalmente pública, documente com o comentário "seguranca-ignore".

**Exemplo de correção:**
```ts
// middleware de autenticação + autorização por perfil
export function autenticar(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ erro: 'Não autenticado' });
  try {
    req.usuario = jwt.verify(token, process.env.JWT_SECRET!, { algorithms: ['HS256'] });
    next();
  } catch {
    return res.status(401).json({ erro: 'Token inválido' });
  }
}

export const exigirPerfil = (...perfis: string[]) => (req, res, next) =>
  perfis.includes(req.usuario?.perfil) ? next() : res.status(403).json({ erro: 'Acesso negado' });

router.delete('/alunos/:id', autenticar, exigirPerfil('admin'), excluirAluno);
```

### 18. 🟡 Acesso a registro pelo id da URL sem verificar o dono (possível IDOR)

| Campo | Valor |
|---|---|
| **Vulnerabilidade** | Acesso a registro pelo id da URL sem verificar o dono (possível IDOR) (`PER-003`) |
| **Arquivo/linha** | `src/routes/alunos.ts:13` |
| **Nível de risco** | 🟡 **Médio** |
| **Categoria** | Permissões |
| **OWASP** | A01:2021 – Broken Access Control |
| **Origem / confiança** | regra / baixa |

**Trecho:**
```ts
const [linhas] = await pool.execute('SELECT * FROM notas WHERE aluno_id = ?', [req.params.id]);
```
**Explicação:** Um registro é buscado/alterado usando apenas req.params.id, e o arquivo não compara esse registro com o usuário autenticado (req.usuario/req.user).

**Impacto:** Trocando o id na URL, um usuário pode ver ou alterar dados de outro (ex.: notas e faltas de outro aluno).

**Recomendação:** Inclua o usuário autenticado no filtro da consulta ou verifique a propriedade do registro antes de retorná-lo; administradores podem ter regra própria.

**Exemplo de correção:**
```ts
const [linhas] = await pool.execute(
  'SELECT * FROM notas WHERE id = ? AND aluno_id = ?',
  [req.params.id, req.usuario.id],
);
if (linhas.length === 0) return res.status(404).json({ erro: 'Não encontrado' });
```

### 19. 🟡 Atribuição em massa (mass assignment) a partir de req.body

| Campo | Valor |
|---|---|
| **Vulnerabilidade** | Atribuição em massa (mass assignment) a partir de req.body (`PER-002`) |
| **Arquivo/linha** | `src/routes/alunos.ts:23` |
| **Nível de risco** | 🟡 **Médio** |
| **Categoria** | Permissões |
| **OWASP** | A01:2021 – Broken Access Control |
| **Origem / confiança** | regra / media |

**Trecho:**
```ts
await pool.query('UPDATE configuracoes SET ?', [req.body]);
```
**Explicação:** O objeto inteiro da requisição é repassado para criação/atualização de registros.

**Impacto:** O usuário pode incluir campos que não deveria controlar (perfil, ativo, notas, id de outro usuário) e alterá-los.

**Recomendação:** Selecione explicitamente os campos permitidos (allowlist) antes de gravar.

**Exemplo de correção:**
```ts
const { nome, email, telefone } = req.body;   // apenas campos permitidos
await Usuario.update({ nome, email, telefone }, { where: { id: req.usuario.id } });
```

### 20. 🟡 Rota de login sem limitação de tentativas

| Campo | Valor |
|---|---|
| **Vulnerabilidade** | Rota de login sem limitação de tentativas (`API-003`) |
| **Arquivo/linha** | `src/routes/auth.ts:9` |
| **Nível de risco** | 🟡 **Médio** |
| **Categoria** | API |
| **OWASP** | A07:2021 – Identification and Authentication Failures |
| **Origem / confiança** | regra / media |

**Trecho:**
```ts
router.post('/login', async (req, res) => {
```
**Explicação:** A rota de autenticação não possui rate limiting identificável no arquivo.

**Impacto:** Permite ataques de força bruta e credential stuffing contra as contas de usuários.

**Recomendação:** Limite tentativas por IP/usuário (ex.: express-rate-limit) e considere bloqueio temporário após falhas.

**Exemplo de correção:**
```ts
import rateLimit from 'express-rate-limit';
const limiteLogin = rateLimit({ windowMs: 15 * 60 * 1000, limit: 10 });
router.post('/login', limiteLogin, login);
```

### 21. 🟡 Token JWT emitido sem tempo de expiração

| Campo | Valor |
|---|---|
| **Vulnerabilidade** | Token JWT emitido sem tempo de expiração (`AUT-004`) |
| **Arquivo/linha** | `src/routes/auth.ts:14` |
| **Nível de risco** | 🟡 **Médio** |
| **Categoria** | Autenticação |
| **OWASP** | A07:2021 – Identification and Authentication Failures |
| **Origem / confiança** | regra / media |

**Trecho:**
```ts
const token = jwt.sign({ id: usuario.id, perfil: usuario.perfil }, JWT_SECRET);
```
**Explicação:** jwt.sign() é chamado sem a opção expiresIn (nem claim exp).

**Impacto:** Um token roubado continua válido para sempre, mesmo após troca de senha ou desligamento do usuário.

**Recomendação:** Defina expiresIn curto (ex.: 15min–8h) e, se necessário, use refresh tokens.

**Exemplo de correção:**
```ts
const token = jwt.sign({ sub: usuario.id, perfil: usuario.perfil }, process.env.JWT_SECRET!, {
  expiresIn: '1h',
  algorithm: 'HS256',
});
```

### 22. 🟡 Cookie de sessão/token sem flags de segurança

| Campo | Valor |
|---|---|
| **Vulnerabilidade** | Cookie de sessão/token sem flags de segurança (`AUT-007`) |
| **Arquivo/linha** | `src/routes/auth.ts:15` |
| **Nível de risco** | 🟡 **Médio** |
| **Categoria** | Autenticação |
| **OWASP** | A07:2021 – Identification and Authentication Failures |
| **Origem / confiança** | regra / media |

**Trecho:**
```ts
res.cookie('token', token);
```
**Explicação:** Um cookie é definido sem httpOnly (ou com secure: false / httpOnly: false).

**Impacto:** Sem httpOnly o token pode ser lido por scripts injetados (XSS); sem secure pode trafegar sem criptografia; sem sameSite fica exposto a CSRF.

**Recomendação:** Defina httpOnly: true, secure: true (em produção), sameSite: "strict" ou "lax" e um maxAge.

**Exemplo de correção:**
```ts
res.cookie('token', token, {
  httpOnly: true,
  secure: process.env.NODE_ENV === 'production',
  sameSite: 'strict',
  maxAge: 60 * 60 * 1000,
});
```

### 23. 🟡 CORS liberado para qualquer origem

| Campo | Valor |
|---|---|
| **Vulnerabilidade** | CORS liberado para qualquer origem (`API-001`) |
| **Arquivo/linha** | `src/server.ts:7` |
| **Nível de risco** | 🟡 **Médio** |
| **Categoria** | API |
| **OWASP** | A05:2021 – Security Misconfiguration |
| **Origem / confiança** | regra / alta |

**Trecho:**
```ts
app.use(cors());
```
**Explicação:** A API aceita requisições de qualquer origem (cors() sem opções, origin: "*" ou origin: true).

**Impacto:** Qualquer site pode chamar a API pelo navegador do usuário; combinado com credenciais, permite ler dados em nome da vítima.

**Recomendação:** Restrinja as origens permitidas ao(s) domínio(s) do front-end, lidos de configuração.

**Exemplo de correção:**
```ts
app.use(cors({
  origin: process.env.FRONTEND_URL?.split(','),   // ex.: https://app.escola.com.br
  credentials: true,
}));
```

### 24. 🟡 Detalhes internos de erro retornados ao cliente

| Campo | Valor |
|---|---|
| **Vulnerabilidade** | Detalhes internos de erro retornados ao cliente (`API-004`) |
| **Arquivo/linha** | `src/server.ts:13` |
| **Nível de risco** | 🟡 **Médio** |
| **Categoria** | API |
| **OWASP** | A05:2021 – Security Misconfiguration |
| **Origem / confiança** | regra / media |

**Trecho:**
```ts
res.status(500).json(err);
```
**Explicação:** O objeto de erro (ou sua stack) é enviado diretamente na resposta HTTP.

**Impacto:** Expõe estrutura do banco, caminhos de arquivos, consultas SQL e versões de bibliotecas, ajudando o atacante a planejar ataques.

**Recomendação:** Registre o erro no log do servidor e devolva ao cliente uma mensagem genérica.

**Exemplo de correção:**
```ts
} catch (erro) {
  logger.error(erro);
  return res.status(500).json({ erro: 'Erro interno. Tente novamente.' });
}
```

### 25. 🔵 Tabela com dados pessoais sem indicação de proteção (LGPD): alunos

| Campo | Valor |
|---|---|
| **Vulnerabilidade** | Tabela com dados pessoais sem indicação de proteção (LGPD): alunos (`BD-004`) |
| **Arquivo/linha** | `database/schema.sql:8` |
| **Nível de risco** | 🔵 **Baixo** |
| **Categoria** | Banco de Dados |
| **OWASP** | A02:2021 – Cryptographic Failures |
| **Origem / confiança** | regra / baixa |

**Trecho:**
```sql
CREATE TABLE alunos (
```
**Explicação:** A tabela contém colunas de dados pessoais (CPF, RG, nascimento, endereço, telefone etc.).

**Impacto:** Dados pessoais exigem controles adicionais pela LGPD; um vazamento gera dano aos titulares e responsabilização da instituição.

**Recomendação:** Colete apenas o necessário, restrinja quem pode consultar esses campos, considere criptografia em repouso para documentos e nunca retorne esses campos em listagens.

**Observação:** Colunas: cpf, data_nascimento, telefone

**Exemplo de correção:**
```sql
-- exemplo: expor somente o necessário por meio de uma view
CREATE VIEW vw_alunos_publico AS
  SELECT id, nome, turma_id FROM alunos;
```

### 26. 🔵 Dados da requisição usados sem validação de esquema

| Campo | Valor |
|---|---|
| **Vulnerabilidade** | Dados da requisição usados sem validação de esquema (`ENT-004`) |
| **Arquivo/linha** | `src/routes/alunos.ts:23` |
| **Nível de risco** | 🔵 **Baixo** |
| **Categoria** | Validação de Entrada |
| **OWASP** | A04:2021 – Insecure Design |
| **Origem / confiança** | regra / baixa |

**Trecho:**
```ts
await pool.query('UPDATE configuracoes SET ?', [req.body]);
```
**Explicação:** O arquivo manipula req.body mas nenhuma validação de esquema (zod, joi, yup, express-validator, class-validator) foi identificada.

**Impacto:** Tipos e formatos inesperados podem causar erros, gravação de dados inválidos (ex.: nota negativa) ou abrir caminho para outras injeções.

**Recomendação:** Valide o corpo de cada requisição com um esquema explícito antes de usá-lo e rejeite campos desconhecidos.

**Exemplo de correção:**
```ts
import { z } from 'zod';
const NotaSchema = z.object({
  alunoId: z.number().int().positive(),
  valor: z.number().min(0).max(10),
}).strict();

const dados = NotaSchema.safeParse(req.body);
if (!dados.success) return res.status(400).json({ erros: dados.error.flatten() });
```

### 27. 🔵 Dados da requisição usados sem validação de esquema

| Campo | Valor |
|---|---|
| **Vulnerabilidade** | Dados da requisição usados sem validação de esquema (`ENT-004`) |
| **Arquivo/linha** | `src/routes/auth.ts:10` |
| **Nível de risco** | 🔵 **Baixo** |
| **Categoria** | Validação de Entrada |
| **OWASP** | A04:2021 – Insecure Design |
| **Origem / confiança** | regra / baixa |

**Trecho:**
```ts
const { email, senha } = req.body;
```
**Explicação:** O arquivo manipula req.body mas nenhuma validação de esquema (zod, joi, yup, express-validator, class-validator) foi identificada.

**Impacto:** Tipos e formatos inesperados podem causar erros, gravação de dados inválidos (ex.: nota negativa) ou abrir caminho para outras injeções.

**Recomendação:** Valide o corpo de cada requisição com um esquema explícito antes de usá-lo e rejeite campos desconhecidos.

**Exemplo de correção:**
```ts
import { z } from 'zod';
const NotaSchema = z.object({
  alunoId: z.number().int().positive(),
  valor: z.number().min(0).max(10),
}).strict();

const dados = NotaSchema.safeParse(req.body);
if (!dados.success) return res.status(400).json({ erros: dados.error.flatten() });
```

### 28. 🔵 Cabeçalhos de segurança HTTP não configurados

| Campo | Valor |
|---|---|
| **Vulnerabilidade** | Cabeçalhos de segurança HTTP não configurados (`API-002`) |
| **Arquivo/linha** | `src/server.ts:6` |
| **Nível de risco** | 🔵 **Baixo** |
| **Categoria** | API |
| **OWASP** | A05:2021 – Security Misconfiguration |
| **Origem / confiança** | regra / media |

**Trecho:**
```ts
const app = express();
```
**Explicação:** O servidor Express é criado sem o helmet (ou equivalente) e mantém o cabeçalho X-Powered-By.

**Impacto:** Facilita a identificação da tecnologia pelo atacante e deixa de aplicar proteções do navegador (clickjacking, MIME sniffing, HSTS).

**Recomendação:** Adicione o helmet logo após criar o app e desabilite X-Powered-By.

**Exemplo de correção:**
```ts
import helmet from 'helmet';
const app = express();
app.use(helmet());
app.disable('x-powered-by');
```
