# TunnelMac — Identidade visual

Conceito: **Tríade**. Três arcos (FortiClient, OpenVPN e WireGuard) fecham um anel em torno de um núcleo: três protocolos, uma conexão privada.

## Estrutura
01-Logo/SVG  Símbolo e logo horizontal (texto convertido em curvas, Manrope SemiBold)
             Versões: color-dark (fundo escuro), color-light (fundo claro), white, black
01-Logo/PNG  Os mesmos, RGBA transparente, lado maior 2048 px
02-AppIcon   AppIcon.svg (mestre editável), AppIcon-1024.png, AppIcon.icns, AppIcon.iconset/
             source/  Mestre otimizado para 16 e 32 px (traço mais grosso, pontas retas)
             Light/   Variante clara completa (SVG, 1024, .icns, .iconset)
03-MenuBar   MenuBarTemplate.svg, MenuBarTemplate.png (18×18), MenuBarTemplate@2x.png (36×36)

## Paleta
Grafite escuro   #0E1720   placa (base) / texto em fundo claro
Grafite          #1E2C38   placa (topo do gradiente)
Névoa            #E9F0F2   núcleo e texto em fundo escuro
Porcelana        #FBFAF7 → #E4E1DA   placa da variante clara

Arcos em fundo escuro:  FortiClient #2E95D6 · OpenVPN #EE8A34 · WireGuard #D0423F
Arcos em fundo claro:   FortiClient #1F7EC2 · OpenVPN #DE7420 · WireGuard #BF3532

## Ícone do app
Grade macOS: tela 1024 × 1024, placa 824 × 824 centrada (margem 100 px), raio 185, sombra inferior.
O .icns sai sempre do iconutil: 16 e 32 px ficam em ic04/ic05 (ARGB). Montado à mão com PNG em icp4/icp5,
o ícone pequeno aparece como ruído na miniatura de janela do Dock e no Mission Control.
Para regerar a partir do iconset:

    iconutil -c icns AppIcon.iconset -o AppIcon.icns
    iconutil -c icns Light/AppIcon-Light.iconset -o Light/AppIcon-Light.icns

## Barra de menus
Imagem template: preto puro + alfa. O macOS aplica a cor (claro/escuro/realce) automaticamente.
Swift:  let img = NSImage(named: "MenuBarTemplate"); img?.isTemplate = true
Em Assets.xcassets, marque "Render As: Template Image". O sufixo "Template" no nome também ativa isso.
Tamanho: 18 × 18 pt.

## Uso
- Área de respiro mínima ao redor do logo: o raio do núcleo do símbolo.
- Tamanho mínimo: símbolo 16 px; logo horizontal 96 px de largura.
- Não recolorir arcos individualmente fora da paleta, não girar o símbolo, não aplicar contorno ou sombra.
