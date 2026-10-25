# Implementação da revisão para 1.0.0

Data: 24/10/2026. Base de trabalho: `67562c3`, com alterações locais não commitadas.
App: **0.5.0-rc.1, build 25**, protocolo do helper **7**.

As correções abaixo foram implementadas. Isso não declara a versão estável: a suíte gráfica, as conexões reais e o ciclo privilegiado ainda precisam ser validados. Nenhum commit, publicação, instalação em `/Applications`, registro de serviço ou conexão real foi realizado nesta rodada.

## Alterações por achado

| ID | Implementação / decisão |
| --- | --- |
| 01 | Conversões exatas e bounds sem overflow no fat Mach-O; load commands curtos são recusados. |
| 02 | Importação recusa `tls-verify` e plugins, exige `remote-cert-tls server`, rejeita TLS 1.0/1.1 e `tls-cert-profile insecure`. Criptografia antiga/compressão gera aviso sem troca automática dos parâmetros. O helper revalida a política. |
| 03 | Aprovação mostra caminho efetivo, avisos do inventário e o risco de executar aquela origem como administrador. A descrição não presume Homebrew. |
| 04 | A gravação do journal precisa funcionar antes de alterar DNS. Escritas protegidas sincronizam o conteúdo antes do rename. |
| 05 | Falhas de restauração preservam backups/journals. Cleanup pendente falha visivelmente e impede novos starts/manutenção. Registro de supervisor falhando cancela a inicialização; registros ilegíveis bloqueiam operações. |
| 06 | Monitor de DNS existe enquanto houver holders, inclusive quando a aplicação inicial foi adiada por outro túnel. |
| 07 | Preparação de diretórios não apaga work files; sweep explícito de recuperação preserva tokens vivos. |
| 08 | Opção conservadora: aprovação/substituição de runtime é recusada enquanto houver sessões vivas/encerrando ou recuperação pendente. |
| 09 | Timeout de start invalida a conexão XPC que possui as sessões; o helper abandona seus starts/sessões. Tokens tardios ainda recebem pedido de stop. Timeouts somente de leitura não desconectam túneis. |
| 10 | Supervisor permite 10 s de SIGTERM e depois encerra o grupo privado do cliente. Reader não depende de EOF de todos os descendentes. Encerramento forçado é reportado como falha; a GUI cancela sua saída após 30 s sem confirmação. Cleanup de rede continua obrigatório. |
| 11 | Bypass do endpoint é estabelecido e verificado antes das rotas capturadoras e de anunciar ready. Falha encerra o setup com diagnóstico; uma nova conexão pode tentar novamente. |
| 12 | Probes possuem grupo privado e prazo de drenagem; descendentes com stdout aberto não anulam o timeout. Há até 1 s de tolerância para SIGTERM antes de SIGKILL. |
| 13 | DNS declarado no perfil WireGuard é requisito: falta de serviço, conflito de proprietário ou falha de aplicação impede ready. OpenVPN sem `dns-updown` protegido não inicia. |
| 14 | Proteção é calculada pela inclusão do endereço do endpoint nos CIDRs efetivos, incluindo dois `/1` e redes parciais. |
| 15 | Intenção de rota é gravada antes da mutação. Verificação de destino/gateway evita remover uma rota substituída. Sessões que compartilham um bypass gerenciado mantêm referências até a última encerrar. |
| 16 | Monitor acompanha endpoints UAPI mesmo depois do primeiro handshake. Mudanças do gateway/interface provocam re-resolução dos endpoints nomeados, com uma resolução em voo por sessão, preservando chaves/configuração dos peers. |
| 17 | Ausência de preferência e seleção inválida deixam o DNS atual intacto. Escolhas explícitas existentes são preservadas. |
| 18 | Consultas automáticas ao Homebrew obedecem à preferência de atualização; consulta manual permanece disponível. Tela e documentação descrevem GitHub e Homebrew. |
| 19 | Drift verifica executável, bibliotecas e scripts em background e compara nova inspeção da instalação atual com o digest aprovado, incluindo mudanças de resolução de symlinks. |
| 20 | Carregamento inicial, preparação de conexão, leitura/gravação SAML, importações, hashes, save/delete, aprovação de certificado, correção de compatibilidade e importação PKCS#12 da interface foram movidos para background. Leituras de perfis/JSON/referências/certificados têm limites por descritor, inclusive contra crescimento concorrente. Gerações descartam resultados antigos das importações principais. |
| 21 | Exclusão mantém operação recuperável e propaga falhas ao remover perfis/cookies/senha. Cadastro não some silenciosamente após erro de limpeza. |
| 22 | Journal de operação com recuperação determinística no próximo início. Senha temporária fica em serviço separado do Keychain, nunca no JSON; perfis continuam privados. Novo JSON nasce 0600 antes da substituição. Falha depois de iniciar uma alteração bloqueia o uso dos dados até recuperação. |
| 23 | Intermediários do PKCS#12 são preservados no Keychain. Exportação constrói cadeia local, sem buscar AIA, com leaf/intermediários e sem acrescentar raízes indiscriminadamente. |
| 24 | Identidade do cookie inclui certificado cliente e versão de digest v2; cookies antigos são invalidados. Renomear continua preservando a identidade. |
| 25 | `VPNApp` contém lógica/UI reutilizável; `VPNGUI` é somente a entrada de produção. Fixtures e modos de teste foram para um pacote `IntegrationRunner` separado. `ReviewTests` é um test target próprio. A GUI não vincula `VPNHelperCore`. |
| 26 | AppModel/casos de uso e persistência separados da entrada SwiftUI/AppKit. JSON, perfis, Keychain, limites de arquivo e transações têm arquivos próprios. A refatoração foi incremental; controladores de sessão/rede continuam encapsulando seu estado, sem divisão artificial de toda a árvore sugerida. |
| 27 | Preflight comum aos dois publicadores: árvore limpa, auditoria, Gitleaks, atestado da suíte e CI do mesmo commit. Estável/prerelease deriva da versão. Auditoria distingue privacidade de possível segredo, aceita somente a linha sintética conhecida e permite triagem por fingerprint exato com justificativa. Nenhuma exceção histórica foi aprovada nesta rodada. |
| 28 | README, SECURITY, changelog, notas, preferências de rede e cask atualizados. Comandos de release checks usam o runner separado. Cask estável não recebe caveat fixo de RC. |

## Validação local final

| Verificação | Resultado |
| --- | --- |
| `scripts/test-regressions.sh` | **23 testes, zero falhas**, aproximadamente 10,8 s. |
| Build release arm64 de GUI/helper/supervisor | **Passou**, build 25. |
| Build debug do pacote `IntegrationRunner` | **Passou**; preparação final por `scripts/test.sh --prepare-only` concluída. |
| Runner separado `--release-checks` inspecionando o bundle final | **4 checks, zero falhas**. |
| `codesign --verify --strict --deep` | **Passou**, assinatura ad hoc. |
| Símbolos/strings da GUI de produção | Sem `VPNHelperCore`, SelfTests/fixtures e argumentos `--self-test`/`--release-checks`. |
| Sintaxe dos scripts shell e compilação Python | **Passaram**. |
| Geração de cask 1.0.0 e 1.0.0-rc.1 | **Passou**; caveat de candidato somente para RC. |
| `git diff --check` | **Passou**. |
| Suíte gráfica completa, `scripts/test.sh` | **Bloqueada na abertura do runner**, após regressões/builds: LaunchServices `-10827`, `kLSNoExecutableErr`. |
| Execução direta do runner com AppKit | **Abort às 18h14**, `SIGABRT`, durante `_RegisterApplication`, antes da suíte. Causa exata não comprovada. Não foi o app instalado. |
| Identidade de assinatura acessível | `security find-identity -v -p codesigning`: **0 identidades válidas** nesta sessão. |
| Auditoria de publicação | **BLOCKED**: 444 blobs, 26 achados de privacidade e 1 achado histórico de padrão de chave privada; zero achados triados. Não equivale a 1 segredo válido comprovado. Gitleaks não está instalado nesta sessão. |

As regressões cobrem: offsets/truncamentos Mach-O; falha de journal e restauração DNS; monitor adiado; work files vivos; CIDRs contendo endpoints; descendentes com pipe aberto; limites de leitura e modo 0600; mudança de identidade SAML; política OpenVPN; interrupções simuladas nas fases de salvar/excluir; preferência de consultas Homebrew; drift de dependência; inspeção dos runtimes locais disponíveis; recusa de JSON excessivo antes de iniciar a transação; falhas de bypass/DNS; cleanup recuperável e rota compartilhada; cliente real sintético ignorando SIGTERM.

As interrupções de persistência usam checkpoints e uma nova instância recuperadora, com Keychain em memória. Não simulam perda de energia. Hosts de rede são simulados: os testes não alteraram DNS, rotas, serviços ou VPNs pessoais. O supervisor executou somente um cliente sintético isolado.

Evidências locais em `build/review-local/RegressionResults.txt`, `ReleaseResults.txt` e bundles nesse diretório. O log de crash do macOS identifica `VPNGUILocalChecks-0.5.0.app`, não `/Applications/TunnelMac.app`.

## Antes de testar conexões reais

1. Em um Terminal com sessão gráfica normal, executar `OUTPUT_DIR="$PWD/build/review-local" ./scripts/test.sh`. Isso ainda usa o runner isolado e não conecta VPNs. A suíte completa precisa concluir; não há atestado de sucesso gráfico nesta rodada.
2. Disponibilizar uma identidade Apple válida no Keychain e gerar um build de teste assinado, usando `SIGNING_IDENTITY` e `TEAM_ID` de `scripts/build.sh`. O bundle ad hoc atual não habilita privilégios e não serve para testar conexões reais.
3. Antes de substituir a instalação, desconectar pelo app anterior e remover seu serviço pelo próprio app, preservando cadastros/senhas. Instalar o novo bundle assinado, ativar o serviço e aprovar novamente os clientes com todas as sessões desligadas. O contrato passou de 6 para 7; um helper antigo será recusado.
4. Testar Fortinet senha/SAML/reuso/certificado cliente, OpenVPN e WireGuard. Conferir DNS e rotas antes/depois, cancelamento no start, desconexão e saída, suspensão/retomada, troca de rede e concorrência entre protocolos. Perfil sem a política TLS exigida deve falhar com explicação.

Não houve commit. A etapa seguinte é validação gráfica e de conexões reais antes de autorizar qualquer commit/release.

## Limites restantes para a 1.0.0

- Teste de start XPC deliberadamente atrasado além do timeout, consentimento visual, cadeia cliente com intermediária contra servidor de teste e regressão gráfica completa ainda precisam de execução no ambiente apropriado.
- Instalação/upgrade/reinstall/unregister/uninstall em VM descartável e falhas reais de disco/configd continuam pendentes. Rede real e concorrência do kernel não são comprovadas pelos mocks.
- Suporte macOS 13+ é o deployment target, não uma matriz executada. Esta rodada é arm64 no host atual; não declara suporte Intel validado.
- Re-resolução usa o resolvedor do sistema em uma tarefa de background, limitada a uma em voo. Não cancela um `getaddrinfo` travado no sistema; a UI e a fila da sessão continuam disponíveis. Não são suportadas políticas arbitrárias de túneis aninhados/conflitos de redes.
- Aprovação de digest/correção de compatibilidade e cache de cookies também usam a fila de persistência na interface. Métodos síncronos equivalentes permanecem como seams para os checks determinísticos. Pequenas consultas de metadados ainda existem na apresentação; a ausência absoluta de I/O no MainActor não foi declarada.
- Journals/mutações são recuperáveis após interrupção de processo; não há prova de durabilidade contra perda de energia ou todos os erros de armazenamento. Logs/arquivos históricos remotos não foram auditados. A triagem de publicação continua bloqueante; histórico não foi reescrito.
- Chaves de perfis e journal de edição permanecem em arquivos privados 0600; o proprietário e seus backups podem lê-los. Isso não equivale ao Keychain. Não há kill switch: falha do túnel pode devolver tráfego à conexão física.
- A 1.0.0 continua condicionada à assinatura/notarização e ao teste do artefato final. Este build é candidato local de validação.
