# TunnelMac — revisão para a versão 1.0.0

Data: 24/10/2026. Versão revisada: `0.5.0-rc.1`, build `24`, protocolo do helper `6`.

Commit de referência: `8551e5c2c6c689b4927e1d0ff14859393237c411`.

## Parecer

**Eu não lançaria a 1.0.0 no estado revisado.** Há problemas de disponibilidade do helper, preservação de políticas de autenticação do OpenVPN, recuperação de rede e acompanhamento de sessões. A arquitetura tem boas proteções, mas alguns caminhos de falha contradizem as garantias descritas na documentação.

Foram registrados **28 achados**: **9 P1**, **17 P2** e **2 P3**. P1 indica prioridade alta para a estabilidade/segurança da 1.0.0, não necessariamente uma vulnerabilidade crítica explorável remotamente. Não foi demonstrada execução arbitrária de código sem consentimento administrativo.

Os achados 01–05 e 08–11, além das validações de ciclo de vida descritas ao final, devem ser resolvidos antes da versão estável. As demais falhas precisam ser corrigidas ou ter uma decisão explícita de escopo e comportamento para a 1.0.0.

## Escopo e método

- Revisão estática do app, contratos XPC, helper root, supervisor C, parsers/importadores, armazenamento, Keychain, DNS/rotas e scripts/workflows de distribuição.
- Inventário do snapshot: 60 arquivos Swift/C/headers, aproximadamente 16.962 linhas; 4.926 linhas em 13 arquivos de testes e fixtures identificados por nome.
- Compilação release arm64 e verificações executadas em cópia isolada. Ambiente: macOS 27.0.1, Apple Silicon, Swift 6.4.
- Reproduções pequenas chamaram o código de produção compilado e hosts simulados. Não modificaram o DNS/rotas do Mac, o app instalado, os serviços registrados ou as VPNs pessoais.
- O repositório recebeu commits durante o começo da leitura. A partir disso, foi extraído um snapshot do commit acima; as conclusões e referências finais se referem a ele.
- Apenas este relatório foi adicionado ao projeto. Nenhuma correção foi implementada, nenhum commit/publicação foi feito.

Esta revisão não comprova ausência de outros defeitos. Não inclui pentest de gateways/IdPs, validação de todos os clientes upstream, inspeção de segredos remotos do GitHub, nem auditoria de todos os binários publicados.

### Evidência e prioridade

- **Reproduzido:** comportamento observado em execução isolada do código relevante.
- **Inspeção:** caminho e condição identificáveis no código; o cenário completo não foi executado contra uma VPN real.
- **P1:** pode quebrar autenticação, deixar sessões sem controle ou comprometer recuperação/disponibilidade de maneira relevante.
- **P2:** defeito funcional, proteção insuficiente ou organização que deve ser tratada na preparação da versão estável.
- **P3:** manutenção/documentação de menor impacto.

## Índice dos achados

| ID | Prioridade | Problema | Evidência |
| --- | --- | --- | --- |
| 01 | P1 | Mach-O universal malformado derruba o parser/helper | Reproduzido |
| 02 | P1 | Importação OpenVPN pode remover a única verificação específica do servidor | Inspeção + aceitação reproduzida |
| 03 | P1 | Aprovação root esconde avisos sobre a origem do código executável | Inspeção |
| 04 | P1 | DNS pode mudar mesmo quando o registro de recuperação não foi salvo | Reproduzido |
| 05 | P1 | Limpeza perde registros mesmo quando não consegue restaurar a rede | Reproduzido parcialmente |
| 06 | P2 | DNS adiado por outro túnel pode nunca ser aplicado | Reproduzido |
| 07 | P2 | Preparação de diretórios apaga arquivos de sessões WireGuard atuais | Reproduzido |
| 08 | P1 | Atualizações de runtime podem remover uma versão ainda em uso | Inspeção |
| 09 | P1 | Timeout de início pode deixar um túnel ativo sem token no app | Inspeção |
| 10 | P1 | Encerramento pode ficar preso indefinidamente | Inspeção |
| 11 | P1 | Erro ao criar a rota externa do endpoint é ignorado | Inspeção |
| 12 | P2 | Timeout de probe não limita a duração real da operação | Reproduzido |
| 13 | P2 | Falha ao aplicar DNS ainda termina em estado conectado | Inspeção |
| 14 | P2 | Proteção do endpoint só reconhece AllowedIPs com /0 literal | Inspeção |
| 15 | P2 | Rotas externas são registradas depois de serem criadas | Inspeção |
| 16 | P2 | Endpoint WireGuard não acompanha mudanças de endereço/roaming | Inspeção |
| 17 | P2 | DNS público é aplicado por padrão sem escolha inicial explícita | Inspeção |
| 18 | P2 | Consultas ao Homebrew ignoram a opção de atualização automática | Inspeção |
| 19 | P2 | Aviso de runtime desatualizado não cobre bibliotecas/scripts | Inspeção |
| 20 | P2 | I/O e hashes potencialmente lentos executam na thread principal | Inspeção |
| 21 | P2 | Exclusão pode deixar perfis com chaves e cookies órfãos sem avisar | Inspeção |
| 22 | P2 | Persistência é transacional apenas enquanto o processo continua vivo | Inspeção |
| 23 | P2 | Exportação do certificado do cliente não inclui intermediários | Inspeção |
| 24 | P2 | Cookie SAML não é invalidado ao trocar o certificado do cliente | Inspeção |
| 25 | P2 | Testes, fixtures e helper core estão no executável de produção | Inspeção |
| 26 | P3 | Responsabilidades e arquivos crescidos dificultam mudanças seguras | Inspeção |
| 27 | P2 | Caminhos de publicação não aplicam os mesmos critérios | Inspeção + scanner executado |
| 28 | P3 | Documentação contém instruções antigas e garantias inconsistentes | Inspeção |

## Segurança e fronteiras de confiança

### 01 — P1 — Entradas Mach-O não confiáveis provocam trap em vez de rejeição

**Onde:** `Sources/VPNHelperCore/MachO.swift:94`, especialmente linhas 105–107; entrada por `RuntimeInspector.inspect` em `RuntimeInspector.swift:78`.

O parser converte offsets/tamanhos `UInt64` de uma fat image diretamente para `Int`. Um valor acima de `Int.max` provoca trap; a soma `offset + size` também pode transbordar antes da comparação. A inspeção acontece antes da autorização administrativa da aprovação. Portanto, um candidato local malformado alcançado pela inspeção pode derrubar o processo root que atende as outras sessões.

**Reprodução:** um Mach-O universal sintético de 40 bytes com a arquitetura arm64 e offset `UInt64.max` encerrou o executável isolado que chamou `MachOImage(file:)` com sinal 5, em vez de retornar `HelperFailure`. Nenhum helper instalado foi usado. Isso comprova o crash do parser; não comprova corrupção de memória ou execução de código.

**Correção proposta:** conversões exatas (`Int(exactly:)`), validação por subtração antes de somar e checks de bounds para toda leitura de load command. O arquivo deve falhar como dado inválido, sem matar o processo.

**Aceite:** corpus de fat32/fat64 com offsets extremos, somas transbordando, comandos curtos e truncamentos; todos retornam erro, e sessões existentes permanecem operacionais.

### 02 — P1 — A normalização OpenVPN pode enfraquecer a autenticação do servidor

**Onde:** `Sources/VPNGUI/OpenVPNImport.swift`, processamento de `OpenVPNRules.dropped`; `Sources/VPNHelperShared/OpenVPNProfile.swift:135` e `:360`.

O importador remove `tls-verify` e plugins com um aviso genérico de execução de programas. Essas extensões podem implementar a única restrição adicional que distingue o servidor esperado de outro certificado emitido pela mesma CA. O perfil resultante continua válido sem `remote-cert-tls`, `verify-x509-name` ou uma política equivalente. O renderer não exige uma alternativa.

**Reprodução parcial:** `OpenVPNProfile.validated` aceitou um perfil mínimo com `client`, `dev tun`, `remote` e `<ca>`, sem verificação específica do servidor. O teste valida a política do app, não um ataque TLS completo.

**Impacto:** um perfil que dependia da validação removida passa a ter outra política de confiança. O ataque exige um certificado/chave aceito pela CA e as condições de rede correspondentes; não significa que qualquer certificado inválido seja aceito.

**Correção proposta:** rejeitar a remoção de validação de identidade sem uma substituição compreendida e configurada pelo usuário. Exibir análise específica de segurança do perfil; manter scripts desabilitados e exigir verificação de papel/identidade apropriada no perfil normalizado.

**Aceite:** importar um perfil cuja única verificação adicional é `tls-verify` não permite conectar silenciosamente com política reduzida. Usar certificados sintéticos de servidor e cliente da mesma CA para verificar a restrição.

Referências primárias: [alerta de MITM do OpenVPN](https://openvpn.net/community-docs/important-note-on-possible--man-in-the-middle--attack-if-clients-do-not-verify-the-certificate-of-the-server-they-are-connecting-to/) e [opções TLS no código oficial](https://github.com/OpenVPN/openvpn/blob/master/doc/man-sections/tls-options.rst). A allowlist também aceita `tls-cert-profile insecure`, TLS 1.0 e escolhas criptográficas antigas sem análise específica; incluir esses casos na mesma política, sem alterar parâmetros criptográficos automaticamente.

### 03 — P1 — Consentimento administrativo não mostra o risco real do candidato

**Onde:** `Sources/VPNGUI/ServiceController.swift`, `approveClient`, `inspect(...thenApprove:)`; `Sources/VPNGUI/ServiceView.swift:33`; `Sources/VPNGUI/Models.swift`, `BinaryLocator`; `Sources/VPNHelperCore/RuntimeInspector.swift`.

A interface dispara `thenApprove: true` e não apresenta `RuntimeInspection.warnings`. Entretanto, o inventário gera avisos relevantes sobre binários, bibliotecas e script de DNS em locais graváveis por usuário. A UI descreve o candidato como instalado pelo Homebrew, enquanto `BinaryLocator` também procura em MacPorts, PATH e `~/.local/bin`. Nome do executável, formato Mach-O e texto de `--help` não autenticam a procedência upstream.

**Impacto:** o administrador pode aprovar código alterado acreditando que está apenas habilitando uma instalação conhecida. A cópia protegida e seus hashes congelam o código, mas não tornam a origem confiável. Existe autorização administrativa; não foi identificado um bypass desse consentimento.

**Correção proposta:** explicar resumidamente a origem efetiva e as condições relevantes antes da aprovação; exigir reconhecimento quando o candidato for fora da origem esperada ou estiver sob controle de outro contexto de escrita. Não é necessário despejar todo o inventário técnico na tela.

**Aceite:** um candidato em PATH fora do Homebrew nunca aparece como Homebrew; avisos de controle de arquivos não desaparecem do fluxo de consentimento.

## DNS, rotas e recuperação

### 04 — P1 — Mudanças de DNS não dependem do sucesso do journal

**Onde:** `Sources/VPNHelperCore/InternetDNS.swift:83`, especialmente `try? save()` na linha 95; `Sources/VPNHelperCore/WireGuardTunnel.swift:457`.

Os controladores preparam o backup e ignoram o erro ao gravá-lo, depois alteram o Dynamic Store. Sem o registro, um crash elimina a informação necessária à restauração.

**Reprodução:** `InternetDNS.acquire` recebeu um caminho de journal cujo diretório não existia. O host simulado passou de `192.0.2.53` para `8.8.8.8`, a função informou sucesso e o arquivo de recuperação continuou ausente.

**Correção proposta:** não efetuar a alteração se o registro não puder ser persistido; reportar a falha ao controlador da sessão. Considerar durabilidade de gravação/rename de acordo com a garantia pretendida, além da atomicidade.

**Aceite:** falha de escrita, permissões e disco cheio preservam o DNS anterior e produzem erro visível.

### 05 — P1 — Falhas de restauração perdem a oportunidade de recuperação

**Onde:** `Sources/VPNHelperCore/InternetDNS.swift:107`; `Sources/VPNHelperCore/WireGuardTunnel.swift:430`, `:539` e `recover`; `Sources/VPNHelperCore/Sessions.swift`, persistência de `SessionRegistry`.

`InternetDNS.restore` zera o estado e apaga o journal mesmo quando `setDNSSetup` falha. O teardown/recovery WireGuard também ignora erros de exclusão de rota e remove o arquivo de recuperação. Ao mudar de serviço principal, uma restauração malsucedida pode ter seu backup substituído pelo do novo serviço. O registro de supervisores também ignora falhas de persistência.

**Reprodução parcial:** o host simulado recusou restaurar o DNS. Ao final de `release`, `9.9.9.9` continuava aplicado, o arquivo de recuperação não existia e `active` era `false`.

**Impacto:** o app pode declarar limpeza concluída quando ainda há configuração pendente. Na falha posterior do processo, a próxima instância não dispõe do registro para reparar a situação.

**Correção proposta:** manter operações pendentes e backups até confirmar a restauração; distinguir recurso alterado externamente de falha do sistema. Só remover registros efetivamente resolvidos. Propagar resultado de cleanup ao estado da sessão/manutenção.

**Aceite:** injetar falha na restauração, reiniciar o controlador/helper e verificar nova tentativa com o backup original intacto.

### 06 — P2 — O DNS que ficou “para depois” não tem monitor

**Onde:** `Sources/VPNHelperCore/InternetDNS.swift:35`.

Se `otherOwner()` for verdadeiro, `acquire` adiciona o holder e retorna antes de `startMonitor()`. Isso ocorre quando uma VPN com DNS da internet é iniciada enquanto um perfil WireGuard controla o DNS e esse controlador ainda não tinha monitor. Após o WireGuard sair, nada reaplica a escolha pendente. Falha na primeira aplicação também deixa holders sem monitor.

**Reprodução:** com `otherOwner = true`, adquirir, mudar o owner para false e aguardar cinco intervalos deixou o DNS original e zero escritas no host.

**Correção proposta:** manter monitor/assinatura de mudanças enquanto houver holders, mesmo sem registro aplicado, e retomar ao liberar a propriedade do DNS.

**Aceite:** WireGuard com DNS → conectar Fortinet → sair do WireGuard aplica a escolha pendente sem outra ação.

### 07 — P2 — Limpeza genérica remove arquivo de nome de uma sessão atual

**Onde:** `Sources/VPNHelperCore/RuntimeStore.swift:147`, linhas 155–157; chamadas em `HelperCore.startWireGuard` e `preparedSupervisor`.

`prepareDirectories()` mistura criação de pastas com remoção de todos os arquivos `wg.*` do workdir. Ela é chamada durante operações normais, inclusive ao iniciar outra sessão. Pode apagar o arquivo que um wireguard-go recém-iniciado acabou de preencher e cujo observador ainda não leu. O modo de produção usa `LOG_LEVEL=error`, portanto o fallback pelo log não é garantido.

**Reprodução:** criar `wg.active.name`, chamar `prepareDirectories` outra vez e verificar o arquivo resultou em `false`. A corrida completa entre dois clientes não foi executada.

**Correção proposta:** mover sweep para uma recuperação explícita, que conheça os tokens vivos. Preparar diretórios não deve remover recursos de sessão.

**Aceite:** dois starts simultâneos e aprovação de runtime durante startup preservam os arquivos das sessões atuais.

### 08 — P1 — Prune de runtimes não considera sessões em uso

**Onde:** `Sources/VPNHelperCore/RuntimeStore.swift`, `install` e `prune(keeping:)` na linha 368; `Sources/VPNHelperCore/HelperCore.swift`, `approve`.

São mantidos somente os runtimes ativo e anterior de cada tipo. A sessão não mantém uma referência contabilizada ao runtime que executa. Após mais de uma aprovação de versão diferente, um runtime antigo ainda utilizado pode ser removido. Isso atinge especialmente o caminho do `dns-updown` OpenVPN em reconexão/encerramento; bibliotecas abertas sob demanda também dependem dos arquivos.

**Correção proposta:** incluir os runtimes usados por sessões vivas/encerrando no conjunto mantido. Como alternativa mais simples, impedir a aprovação/substituição enquanto houver sessões que usam o tipo correspondente.

**Aceite:** iniciar com runtime A, aprovar B e C e desconectar/reconectar a sessão A; seus recursos permanecem até o cleanup terminar.

### 09 — P1 — Timeout de start descarta uma resposta que contém um túnel real

**Onde:** `Sources/VPNGUI/HelperClient.swift:113`, `Once`; `Sources/VPNGUI/ServiceController.swift`, starts com timeout de 30 segundos; `Sources/VPNGUI/Runtime.swift`, `launch`.

O timeout conclui a chamada com falha, mas não cancela a requisição no helper. Se o helper concluir o start depois do prazo, o token chega a `Once.call` com o callback já removido. A resposta é descartada e o tratamento de token tardio do `VPNManager.launch` não roda. O app perde o identificador necessário para desconectar; eventos desse token também são ignorados. A conexão XPC pode continuar aberta, mantendo o túnel no helper.

É alcançável sob fila congestionada: instalação de runtime e outras operações demoradas executam na mesma fila que atende starts.

**Correção proposta:** request ID idempotente com cancelamento/reconciliação; ou invalidar o canal ao timeout de operação mutável, aguardando cleanup comprovado. Respostas tardias de start precisam ser processadas para encerrar a sessão, mesmo depois de reportar erro à UI.

**Aceite:** atrasar o início além do timeout e comprovar que não sobra processo nem rota/DNS sem sessão controlável pelo app.

### 10 — P1 — STOP não garante progresso e pode impedir sair do app

**Onde:** `Sources/VPNSupervisor/main.c`, loop final de `waitpid`; `Sources/VPNHelperCore/Sessions.swift`, `stop`/`startReading`; `Sources/VPNGUI/App.swift`, `terminationReply`.

O supervisor envia SIGTERM uma vez e aguarda sem prazo. O reader aguarda EOF e depois `waitpid` bloqueante. O app retorna `terminateLater` até as sessões ficarem inativas, também sem saída para o caso de um cliente travado. Um cliente que não encerra mantém o fluxo preso.

O prazo de 15 segundos de `HelperCore.shutdown` limita apenas a espera do helper. Não comprova que os processos acabaram nem que o WireGuard teve seu observador de cleanup executado. EOF pede encerramento, mas não garante sua conclusão.

**Correção proposta:** definir estados e prazos de encerramento, informar claramente limpeza pendente e oferecer recuperação controlada. Qualquer escalonamento deve respeitar diferenças entre protocolos e evitar declarar sucesso antes de limpar recursos; simplesmente adicionar SIGKILL não resolve a parte de rede.

**Aceite:** cliente sintético que ignora SIGTERM não congela indefinidamente o fluxo sem diagnóstico; reinício/recuperação de helper trata os recursos pendentes.

### 11 — P1 — WireGuard ignora falha na rota que mantém o servidor fora do túnel

**Onde:** `Sources/VPNHelperCore/WireGuardTunnel.swift:406`, `refreshEndpointRoutes`; chamada por `bringUp`.

Depois de instalar as rotas de túnel completo, o código cria a rota do endpoint com `required: false` e não falha se o comando for recusado. `lastDesired` é atualizado antes do sucesso, então uma tentativa fracassada não é repetida enquanto o gateway desejado não mudar. A sessão pode atingir o marcador de configurada com os pacotes destinados ao próprio servidor entrando no túnel.

**Correção proposta:** estabelecer/verificar o bypass necessário antes de declarar a configuração pronta; registrar apenas operações confirmadas e repetir falhas transitórias. Uma rota já existente só deve ser aceita após conferir destino/gateway/interface apropriados.

**Aceite:** simular falha inicial de rota e sucesso posterior; o app não permanece “conectado” sem bypass funcional e sem nova tentativa.

### 12 — P2 — Probe com timeout pode continuar bloqueada por descendentes

**Onde:** `Sources/ProcessBridge/ProcessBridge.c`, `vpn_run_probe`.

O timeout sinaliza o filho direto, mas a função continua drenando o pipe até EOF. Um descendente que herda stdout/stderr mantém o canal aberto mesmo se o processo original saiu. Um programa que deixa descendente persistente pode prender a operação indefinidamente. Os probes de runtime ocorrem após autorização; ferramentas do sistema também usam esse mecanismo.

**Reprodução:** executar `/bin/sh` que cria `sleep 3` em background e sai, com timeout de 100 ms, retornou somente depois de aproximadamente 3.033 ms.

**Correção proposta:** prazo absoluto para leitura/espera, propriedade explícita dos processos criados e fechamento dos descritores após expiração; não depender de EOF de todos os descendentes.

**Aceite:** filho que termina deixando stdout aberto em descendente não mantém a chamada além do limite documentado.

### 13 — P2 — DNS exigido pelo perfil falha sem mudar a saúde da conexão

**Onde:** `Sources/VPNHelperCore/WireGuardTunnel.swift`, `applyDNS`/`setDNS`; `Sources/VPNHelperCore/RuntimeInspector.swift`, ausência de dns-updown; `Sources/VPNGUI/Runtime.swift`, marcadores de conectado.

O WireGuard segue até `ready()` quando não consegue aplicar DNS, quando não encontra serviço principal ou quando outro túnel já é dono do DNS. O runtime OpenVPN pode ser aprovado sem script de DNS, com um aviso que a UI de aprovação não mostra. O app pode indicar conexão normal enquanto nomes internos falham ou seguem ao resolvedor atual.

**Correção proposta:** modelar saúde de túnel e DNS separadamente. Mostrar estado degradado; quando DNS do perfil for requisito, impedir sucesso silencioso. Decidir uma política única para concorrência com OpenVPN, WireGuard e o DNS da internet.

**Aceite:** a UI identifica DNS não aplicado e não depende da leitura do log para comunicar a limitação.

### 14 — P2 — A exceção de roteamento do endpoint depende de /0 literal

**Onde:** `Sources/VPNHelperShared/WireGuardProfile.swift`, `routesAllIPv4`/`routesAllIPv6`; `Sources/VPNHelperCore/WireGuardTunnel.swift`, `addRoute` e `refreshEndpointRoutes`.

O bypass do servidor só é preparado se existe um CIDR com prefixo zero. Um perfil cobrindo a internet com `0.0.0.0/1` e `128.0.0.0/1` não satisfaz o teste. O mesmo problema existe para um túnel parcial cuja rede inclui o IP do próprio endpoint. As rotas aceitas podem capturar os pacotes externos do WireGuard.

**Correção proposta:** calcular se o endpoint cai nas rotas efetivas e preservar seu caminho externo independentemente de como AllowedIPs foi escrito. Tratar política de túneis aninhados de forma explícita.

**Aceite:** perfis /0, dois /1 e uma sub-rede contendo o endpoint mantêm comunicação com o peer.

### 15 — P2 — Journal das rotas tem uma janela após a alteração

**Onde:** `Sources/VPNHelperCore/WireGuardTunnel.swift:406`, criação de rota seguida de `record.routes.append` e `try? saveRecord()`.

A rota externa é criada antes da persistência. Um crash entre essas operações deixa rota sem registro. Além disso, falha ao gravar é ignorada. Isso contraria a afirmação de que as alterações externas são registradas antes de ocorrerem.

**Correção proposta:** journal de intenção persistido antes da mutação e confirmação depois, com recuperação idempotente e verificação de propriedade da rota. O recovery não deve apagar por destino uma rota que já foi substituída por outro responsável.

**Aceite:** interrupção em cada etapa criação/persistência não deixa rota órfã nem remove uma rota externa substituta.

### 16 — P2 — Monitor de endpoints fica preso ao endereço resolvido no início

**Onde:** `Sources/VPNHelperCore/WireGuardTunnel.swift`, `resolveEndpoints`, `tick` e campo `endpoints`.

O hostname é resolvido uma vez; o monitor mantém as exceções para os IPs dessa resolução. Não atualiza as rotas usando o endpoint atual reportado pelo UAPI, nem refaz a resolução após mudança de rede. Uma mudança de IP ou roaming do peer pode deixar o bypass apontando ao endereço antigo e interromper um túnel completo.

**Correção proposta:** acompanhar endpoint efetivo/alterações de rede e definir re-resolução com limites, sem interromper sessões saudáveis desnecessariamente.

**Aceite:** mudança sintética do IP do endpoint e troca Wi-Fi/Ethernet atualizam as exceções e removem as antigas com segurança.

### 17 — P2 — O app altera o DNS global por padrão

**Onde:** `Sources/VPNGUI/AppPreferences.swift:55`, `InternetDNSChoice.swift`; `Sources/VPNHelperCore/InternetDNS.swift`.

Novas instalações e preferências antigas sem a chave de DNS recebem Cloudflare como padrão. Assim, uma atualização pode começar a substituir o DNS da rede quando uma VPN sobe, mesmo sem o usuário escolher isso. Redes corporativas, DNS com filtragem e nomes internos não anunciados como domínios suplementares podem mudar de comportamento. O monitor reaplica a escolha após mudanças da rede.

**Correção proposta:** preferir “Não alterar” na migração e pedir uma escolha clara para usar DNS público; explicar alcance e precedência. Se o comportamento for mantido como decisão de produto, documentar e validar expressamente a migração.

**Aceite:** atualizar uma instalação anterior não muda a política de DNS sem uma decisão visível do usuário.

## Privacidade, persistência e experiência operacional

### 18 — P2 — A opção de atualizações não cobre as consultas de versões dos clientes

**Onde:** `Sources/VPNGUI/ClientStatus.swift:89`; `Sources/VPNGUI/ServiceView.swift`, `onAppear`/`onChange`; `SECURITY.md`.

Abrir a aba de serviço faz GETs para a API pública do Homebrew para os três clientes, sem consultar `AppPreferences.checkForUpdates`. A documentação afirma que a consulta ao GitHub é a única conexão adicional e pode ser desligada. A implementação não corresponde a essa descrição.

**Correção proposta:** oferecer controle coerente para as consultas automáticas, manter ação manual disponível e atualizar a descrição de tráfego de rede. Não há evidência de envio de credenciais nesses requests.

**Aceite:** com consultas automáticas desligadas, abrir a aba não dispara chamadas externas; consulta manual continua funcionando.

### 19 — P2 — Mudança de dependências não aparece como aprovação desatualizada

**Onde:** `Sources/VPNGUI/ClientStatus.swift:89`; `Sources/VPNGUI/ServiceController.swift`, `sourceDrift`; `Sources/VPNHelperCore/RuntimeStore.swift`, `RuntimeManifest.sources`.

O aviso compara apenas os bytes do executável original. Atualização de OpenSSL, outra dylib ou `dns-updown`, sem alteração do executável principal, não aparece como alteração da origem. Como o runtime é uma cópia congelada, pode continuar executando dependência antiga enquanto a interface diz estar atualizado.

**Correção proposta:** comparar o inventário completo com o snapshot aprovado ou receber do helper uma avaliação específica de drift. Separar “mesma versão do executável” de “todas as dependências atualizadas”.

**Aceite:** alterar uma biblioteca/script de fixture mantendo o binário principal produz aviso de nova aprovação necessária.

### 20 — P2 — Operações de disco/Keychain podem bloquear a interface

**Onde:** `Sources/VPNGUI/ClientStatus.swift:89`; `Sources/VPNGUI/ServiceController.swift`, `sourceDrift`; `Sources/VPNGUI/App.swift`, `save`/`connect`; `Sources/VPNGUI/ConnectionEditor.swift`, importações e `importPKCS12`; `Sources/VPNGUI/Models.swift`, `ProfileStore.read`.

Existem leituras integrais, hashes e importações no MainActor. Arquivos escolhidos em volume de rede, binários maiores ou Keychain aguardando interação podem parar a UI, inclusive enquanto precisa exibir eventos ou pedir desconexão. Alguns limites são checados somente após `Data(contentsOf:)`; `connections.json` não tem limite global de tamanho.

**Correção proposta:** executar I/O em serviços fora do MainActor e aplicar os resultados na UI; usar descritores e leituras limitadas antes de carregar todo o conteúdo. Capturar geração/cancelamento para descartar importações antigas.

**Aceite:** leitura lenta e arquivo excessivo não congelam a janela/menu, e o limite de bytes vale também para arquivos crescendo durante a leitura.

### 21 — P2 — Excluir cadastro pode deixar material secreto órfão

**Onde:** `Sources/VPNGUI/App.swift:117`, `delete`.

Depois de remover a conexão do JSON, falhas ao excluir cookie, perfil OpenVPN e perfil WireGuard são ignoradas com `try?`. O cadastro desaparece, mas uma chave privada pode continuar no disco ou um cookie no Keychain sem representação na interface.

**Correção proposta:** reportar limpeza parcial e manter uma operação recuperável de exclusão/sweep dos arquivos sem referência. Distinguir a retenção intencional de dados no uninstall de um erro ao excluir um cadastro específico.

**Aceite:** falha de permissão ao apagar um perfil mostra a pendência e permite concluir a limpeza depois.

### 22 — P2 — Não existe transação recuperável entre perfil, senha e JSON

**Onde:** `Sources/VPNGUI/App.swift:58` e `:117`; `Sources/VPNGUI/Models.swift`, `JSONStore.save` e `ProfileStore.write`.

O rollback existe somente no `catch` da mesma execução. Queda entre gravação do perfil/Keychain e gravação do JSON deixa alterações parciais. Na exclusão, a senha pode sumir antes de o cadastro ser removido. Falhas do próprio rollback também são ignoradas. `JSONStore.save` substitui o arquivo antes de ajustar permissões; se esse ajuste falhar, retorna erro após já ter persistido o novo JSON, enquanto o AppModel tenta reverter outros recursos.

**Correção proposta:** operação em etapas com journal e recuperação no próximo início, ou outra estratégia que mantenha uma versão consistente recuperável. Criar o novo JSON com permissões finais antes da troca.

**Aceite:** interromper o processo em cada etapa de salvar/excluir não troca chaves silenciosamente, não perde credenciais sem aviso e deixa uma recuperação determinística.

### 23 — P2 — Certificado do cliente é exportado apenas como leaf

**Onde:** `Sources/VPNGUI/ClientIdentities.swift:41`, construção de `certificate`; `importPKCS12` não preserva a cadeia no modelo.

A exportação constrói o PEM apenas com `SecCertificateCopyData(match.certificate)`. Um PKCS#12 com intermediários pode ser importado, mas a requisição para o openfortivpn contém apenas o certificado final. Em um servidor que dependa da cadeia enviada pelo cliente, a autenticação pode falhar embora o material importado estivesse completo.

**Correção proposta:** construir a cadeia adequada a partir do Keychain/PKCS#12 e exportar leaf mais intermediários necessários; não incluir raízes indiscriminadamente.

**Aceite:** fixture com CA raiz, intermediária e certificado cliente funciona contra um servidor de teste que não possui a intermediária previamente.

### 24 — P2 — Troca de identidade cliente não invalida a sessão SAML

**Onde:** `Sources/VPNGUI/SAMLCookie.swift:11`, `SAMLCookieIdentity`; `Sources/VPNGUI/App.swift:90`.

O digest inclui servidor, porta, usuário, autenticação, certificado confiável do gateway e realm, mas não `clientCertificate.sha1`. Trocar/remover o certificado cliente mantém o cookie da autenticação anterior. O gateway continua responsável por aceitar ou recusar, porém a ação de trocar identidade no app não garante nova autenticação com essa identidade.

**Correção proposta:** incluir o identificador do certificado cliente na identidade do cache e definir migração que invalide cookies antigos quando essa informação não estava no digest.

**Aceite:** renomear preserva o cookie; mudar/remover o certificado cliente invalida e inicia autenticação nova.

## Organização e preparação de release

### 25 — P2 — Código de testes faz parte do produto distribuído

**Onde:** `Package.swift:21`; `Sources/VPNGUI/App.swift`, branches `--self-test`/`--release-checks`; `*Tests.swift`, `HelperFixtures.swift`, `TestSupport.swift`, `UIReviewFixture.swift`.

O target executável da UI inclui os testes, fixtures e vínculo com `VPNHelperCore` para executar verificações locais. Aproximadamente 4.926 linhas de testes/fixtures identificados por nome ficam na mesma árvore de produção. Há material criptográfico de teste, criação de keychains/listeners/processos e caminhos de verificação acessíveis por argumentos. Isso não constitui, por si só, acesso ao helper real nem bypass da assinatura: o problema é acoplamento, superfície desnecessária e dificuldade de garantir o conteúdo da release.

**Correção proposta:** target de biblioteca para lógica testável, targets de teste separados e um runner de integração/visual dedicado. A GUI de produção deve depender dos contratos necessários, não do helper core apenas para testar.

**Aceite:** build de distribuição exclui testes, fixtures e modos de teste; a suíte continua exercitando o mesmo código de produção em runner separado.

### 26 — P3 — Arquivos acumulam responsabilidades distintas

**Onde:** `Sources/VPNGUI/App.swift`, `Runtime.swift`, `Models.swift`, `ConnectionEditor.swift`, `MainWindow.swift`; `Sources/VPNHelperCore/RuntimeStore.swift`, `WireGuardTunnel.swift`.

Exemplos concretos: `App.swift` mistura persistência/orquestração, ciclo de encerramento, cenas, bridges de NSWindow e UI de testes; `Models.swift` reúne parsing de endereço, entidades, localização de binários, JSON, perfis e Keychain; `Runtime.swift` concentra interpretação de logs, estado, retry, SAML, credenciais e transporte. `ConnectionEditor.swift` também contém painéis de arquivos e limpeza de originais. `RuntimeStore.swift` mistura armazenamento, probes, patch/signing, retenção e certificados temporários.

**Correção proposta:** refatorar por responsabilidade, preservando regras compartilhadas. Sugestão incremental:

```text
VPNGUI/App/               cenas, delegate e integração AppKit
VPNGUI/Connections/       modelo de apresentação e casos de uso
VPNGUI/Views/             janelas, editor e menu
VPNGUI/Persistence/       JSON, perfis, Keychain e recuperação
VPNGUI/Updates/           feeds e estado de atualização
VPNHelperCore/Runtime/    inspeção, instalação, integridade e retenção
VPNHelperCore/Sessions/   processo, eventos e encerramento
VPNHelperCore/Network/    rotas, DNS e journal
Tests/                   testes unitários e fixtures
IntegrationRunner/       XPC, Keychain e verificações gráficas
```

Essa árvore é uma proposta de organização, não uma necessidade de criar todos os diretórios de uma vez. Priorizar separar os casos de uso de salvar/excluir e o journal de rede; apenas dividir arquivos sem diminuir acoplamento não resolve.

### 27 — P2 — Publicação possui caminhos com proteções divergentes

**Onde:** `.github/workflows/release.yml`; `scripts/publish-release.sh`; `scripts/audit-publication.py`; `scripts/update-tap.py`.

O script local exige auditoria, CI e atestado do commit. O workflow faz sua própria suíte, mas não executa a auditoria de publicação nem exige o resultado de `checks.yml`. O script local sempre cria `--prerelease`, mesmo quando a versão futura for `1.0.0`; o workflow trata esse campo de outra forma. A política pode variar conforme o caminho escolhido.

O scanner atual encerrou com **BLOCKED**: 443 blobs examinados, 4 ocorrências de padrão de chave privada, 7 de gateways, 8 de caminhos pessoais, 10 de e-mail pessoal e 1 de identidade de assinatura. Esses números são ocorrências de regra por localização, não quantidade de segredos válidos. A chave na árvore atual é uma fixture explicitamente falsa em `OpenVPNTests.swift:12`; e-mail de autor de commit tampouco equivale a credencial. Os demais resultados históricos precisam de triagem privada. Nenhum valor sensível é reproduzido neste relatório.

**Correção proposta:** centralizar o preflight de publicação e usá-lo em ambos os caminhos; tratar classificação estável/prerelease pela versão; usar scanner de segredos apropriado e exceções estritas para fixtures conhecidas. Separar exposição de dados pessoais de segredo acionável. Confirmar remotamente releases/assets/logs quando houver acesso, sem inferir que o scan local cobriu isso.

**Aceite:** a mesma árvore/versão recebe o mesmo resultado local e no workflow; 1.0.0 não é marcada prerelease por engano. Os controles devem ficar verdes com evidência de triagem, não por desativação indiscriminada das regras.

### 28 — P3 — Documentação mistura estado publicado, implementação e garantias ainda não verificadas

**Onde:** `README.md`, `SECURITY.md`, `CHANGELOG.md`, `packaging/release-notes.md`, `scripts/update-tap.py`.

O README identifica uma release publicada 0.3.0-rc.5 enquanto descreve recursos 0.4/0.5 e usa `./build/0.3.0/...` nas instruções. Isso pode ser uma distinção válida entre publicado e desenvolvido, mas não está clara nos comandos. A documentação descreve o GitHub como única conexão adicional, já desmentido pelas consultas ao Homebrew; afirma registro de rotas antes da alteração, contrário ao fluxo atual; também precisa refletir certificados/chaves persistidos em perfis e os limites reais de cleanup. O template do cask não cita WireGuard na descrição/instruções de aprovação e mantém texto fixo de release candidate.

**Correção proposta:** atualizar documentação e release notes junto com o comportamento final, distinguir claramente release publicada de desenvolvimento e gerar comandos/versionamento a partir de uma fonte coerente.

**Aceite:** alguém instala, ativa, importa cada protocolo, atualiza e remove seguindo somente o material da 1.0.0, sem depender de instruções de outra versão.

## Verificações executadas

| Verificação | Resultado | Limite da conclusão |
| --- | --- | --- |
| Build release arm64 do snapshot, por `scripts/test.sh` | Passou | Assinatura ad hoc; não prova ativação root/notarização |
| `VPNGUI --release-checks` no bundle isolado | 4 checks passaram, zero falhas | Não substitui suíte gráfica nem lifecycle root |
| Suíte completa por `scripts/test.sh` | Não iniciou os testes gráficos | LaunchServices recusou abrir o runner: OSStatus `-10827`, `kLSNoExecutableErr` |
| `bash -n` nos scripts shell | Passou | Somente sintaxe |
| `py_compile` nos dois scripts Python, com cache isolado | Passou | Somente compilação/sintaxe |
| Harness com `InternetDNS`, `RuntimeStore`, `OpenVPNProfile` reais compilados | Comportamentos dos achados 02, 04, 05, 06 e 07 observados | Hosts DNS simulados; sem alterar a rede real |
| Parser Mach-O com fat64 inválido | Trap/sinal 5 | Executável isolado; não foi derrubado o helper instalado |
| `vpn_run_probe` real, filho com descendente mantendo pipe | ~3.033 ms para timeout de 100 ms | Demonstra extrapolação do prazo; nenhum processo pessoal afetado |
| Scanner de publicação existente | BLOCKED, conforme achado 27 | Histórico local alcançável; resultados exigem triagem |

Houve uma primeira tentativa de compilação Python impedida pelo cache fora do workspace; repetição com `PYTHONPYCACHEPREFIX` temporário passou. Uma tentativa de `swift test` foi impedida pelo cache do compilador neste ambiente; o pacote também não declara `.testTarget`, pois sua suíte atual usa o executável/runner. Esses erros de ambiente não foram classificados como bugs funcionais do app.

O build emitiu avisos de APIs antigas de Keychain nas fixtures, captura forte/fraca de `self` em `Runtime.swift` e uso de `--build-system native` deprecado. São itens de manutenção; não foram promovidos a vulnerabilidades sem evidência.

## Validações pendentes para declarar estabilidade

Estas são lacunas de evidência, não vulnerabilidades comprovadas:

1. **Ciclo de vida root em VM descartável:** instalação limpa, ativação/recusa de aprovação, upgrade, reinstall, unregister, uninstall e migração dos nomes antigos. Executar com app aberto, sessão iniciando, VPN conectada e cleanup pendente.
2. **Matriz de macOS:** o app declara macOS 13+, mas esta rodada só compilou no SDK 27/host 27.0.1. Rodar os sistemas realmente suportados, incluindo comportamento das APIs de XPC/SMAppService e fallback visual. Se isso não for viável, ajustar o mínimo suportado.
3. **Arquiteturas:** esta revisão verificou arm64. Intel não deve ser prometido com base apenas em cross-compilation; o empacotamento atual o exclui expressamente.
4. **Concorrência real:** Fortinet + OpenVPN + WireGuard, dois WireGuards, usuários diferentes, redes sobrepostas, mesmo endpoint externo e DNS concorrente. Hoje os mocks de rota retornam sucesso em vários cenários sem simular os conflitos reais do kernel.
5. **Falhas de infraestrutura:** disco cheio, journal sem escrita, Dynamic Store indisponível, SIGTERM ignorado, reinício do helper, perda de XPC, suspensão/retomada e troca da rede principal.
6. **Autenticação:** SAML com cancelamento/timeout/reuso recusado, expiração e troca do certificado cliente; certificados com intermediários; OpenVPN com política específica de servidor e rejeição de certificado cliente apresentado como servidor.
7. **Proteção de tráfego:** não existe kill switch evidente no código revisado. Perda do túnel pode restaurar conectividade pela rede física. Não apresentar reconexão automática como garantia de bloqueio de vazamento; definir o comportamento esperado na documentação/testes. Ausência de kill switch, por si só, não foi contada como bug.
8. **Chaves em repouso:** os perfis OpenVPN/WireGuard guardam chaves privadas em arquivos privados 0600, opção explícita da implementação. Isso não equivale a Keychain: o próprio usuário e seus backups podem ler/copiar o material. Definir o modelo de ameaça e decidir se a 1.0 manterá isso ou armazenará os segredos no Keychain. Não foi classificado como vazamento entre usuários sem prova.
9. **Release final:** notarização, stapling, Gatekeeper e ativação do helper com o artefato efetivamente publicado; confirmar permissões do ambiente de release e proteção de secrets diretamente no GitHub. Configuração remota não foi auditada nesta rodada.

## Proteções existentes que devem ser preservadas

- GUI sem root e helper com operações tipadas; não há API genérica de shell, PID arbitrário ou caminho de saída root controlado pelo perfil.
- Autenticação XPC nos dois sentidos por assinatura Apple, identificador esperado e mesmo Team; builds ad hoc falham fechados para privilégios.
- Revalidação dos perfis no helper, allowlists de opções, recusa de hooks WireGuard e isolamento do script OpenVPN aprovado.
- Cópia gerenciada dos executáveis/dependências, hashes e verificação de ownership antes de execução.
- Configuração por descritor de arquivo anônimo e cookies por pipe; credenciais não são montadas em argv.
- Keychain para senhas/cookies, expiração limitada do cache SAML, filtragem de saída e limites de logs/eventos.
- Atualizador do app limitado a informar releases; sem execução automática de assets ou comandos Homebrew.
- Identificadores legados mantidos conscientemente para preservar compatibilidade. Não renomeá-los apenas para acompanhar a marca sem uma migração planejada.

## Ordem sugerida de correção

1. **Segurança e controle:** 01–03, 09–10. Parser total, política OpenVPN preservada, consentimento bem informado e nenhum start sem sessão controlável.
2. **Recuperação de rede:** 04–08 e 11–16. Journal confiável, retenção de recursos em uso, DNS coordenado e rotas de endpoint verificadas.
3. **Dados e comportamento:** 17–24. Escolhas de DNS/privacidade, I/O fora da UI e persistência/exclusão recuperáveis.
4. **Organização e distribuição:** 25–28. Separar runner de produção, reduzir acoplamento, unificar gates e atualizar documentação.
5. **Candidato de estabilização:** executar a matriz pendente e corrigir regressões antes de marcar a 1.0.0. A aprovação deve se referir ao commit e ao artefato final validados.

## Critério de saída para a 1.0.0

- Todos os P1 resolvidos e cobertos por reproduções de regressão; P2 restantes com decisão explícita e consequência documentada.
- Nenhum cenário de timeout/cancelamento deixa túnel sem controle ou limpeza sem registro recuperável.
- Falhas de DNS/rotas são visíveis e o estado da interface corresponde ao estado operacional verificado.
- Suíte completa passa em ambiente gráfico apropriado e lifecycle privilegiado passa em VM, com logs sanitizados.
- Plataforma mínima e protocolos suportados são demonstrados, não inferidos da compilação.
- Artefato final assinado/notarizado, gates de publicação coerentes e triagem de privacidade/segredos concluída.
