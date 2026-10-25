# Chat News

Chat cifrado ponta a ponta que funciona sem internet, numa rede Wi-Fi local ou num hotspot de telemóvel.

## Como usar

1. Num computador com Node.js 18 ou mais recente, corre na pasta do projeto (o `npm install` só é preciso da primeira vez):

   ```
   npm install
   npm start
   ```

2. O terminal mostra um endereço do tipo `https://192.168.1.20:8443`. Os teus amigos, ligados à mesma rede, abrem esse endereço no browser.
3. O browser vai avisar que o certificado não é de confiança. É normal: foi gerado pelo teu computador. Aceita, ou instala o certificado (ver abaixo) para o aviso desaparecer de vez.
4. Cada pessoa escolhe um nome e escreve a mesma palavra-passe. Quem tem a mesma palavra-passe fica na mesma sala.
5. Confirmem o código ao lado de "Sala" (ex.: `7968-a47b`). Se for igual em todos, estão na mesma sala.

Sem internet nenhuma: liga o hotspot num telemóvel, liga o computador e os amigos a esse hotspot, e pronto.

## Notificações

No chat, carrega em "Avisos". Há notificações do sistema, som e um contador de mensagens por ler no separador do browser.

Limite honesto: os avisos só funcionam enquanto o chat está aberto no browser, mesmo em segundo plano. Notificações com o browser fechado precisariam dos servidores da Google ou da Apple, ou seja, de internet.

- **Android:** é obrigatório instalar o certificado, senão o Chrome não permite notificações.
- **iPhone:** instala o certificado, adiciona o chat ao ecrã principal (Partilhar, "Adicionar ao ecrã principal") e abre-o sempre a partir desse ícone.
- **Computador:** funciona logo, basta autorizar.

## Certificado (uma vez por aparelho)

Na primeira execução o servidor cria uma autoridade de certificação própria na pasta `data/`. Cada aparelho descarrega-a no botão "Avisos" e instala-a seguindo as instruções que lá aparecem. A partir daí o aviso de segurança desaparece.

O certificado está limitado a endereços de rede local (192.168.x.x, 10.x.x.x, 172.16-31.x.x) e a `localhost`. Mesmo que alguém roubasse a chave do teu PC, não a conseguiria usar para se fazer passar por sites da internet nesses telemóveis.

Quando o computador muda de rede, o servidor gera um certificado novo para o IP novo, assinado pela mesma autoridade. Os telemóveis não precisam de reinstalar nada.

Não apagues `data/ca.pem` nem `data/ca-key.pem`. Se os apagares, todos os aparelhos têm de instalar o certificado outra vez. O terminal mostra a impressão digital do certificado, que podes comparar com a que aparece no telemóvel ao instalar.

## Alcance

O alcance é o da rede Wi-Fi:

- hotspot de telemóvel: cerca de 10 a 30 metros;
- router doméstico: uma casa;
- router de viagem ou ponto de acesso exterior: 50 a 150 metros ao ar livre;
- para cobrir mais, junta repetidores ou um sistema mesh. O chat funciona igual porque continua a ser a mesma rede.

## O que está protegido

- As mensagens são cifradas no browser com AES-256-GCM. A chave sai da palavra-passe via PBKDF2 (600 000 iterações).
- O servidor só guarda texto cifrado e um identificador da sala. Não vê nomes, mensagens nem a palavra-passe.
- Mensagens escritas sem ligação ficam em espera e são enviadas quando a rede volta.
- Quem entra mais tarde recebe as últimas 500 mensagens da sala.

## Fotos e ficheiros

- Carrega no clipe ao lado da caixa de texto. No telemóvel podes escolher a câmara, a galeria ou um ficheiro. No computador também podes arrastar ficheiros para a conversa ou colar uma imagem.
- As fotos são reduzidas para no máximo 2048 px antes de serem enviadas. Isto poupa espaço e apaga os metadados, incluindo a localização GPS que os telemóveis guardam nas fotos.
- Os outros ficheiros vão tal como estão, até 25 MB cada.
- Tudo é cifrado no browser antes de sair. No servidor só ficam bytes cifrados.
- Cada sala guarda no máximo 1 GB de ficheiros. Quando passa disso, os mais antigos são apagados.

## Limites que deves conhecer

- A segurança depende da palavra-passe. Usa 4 ou 5 palavras ao acaso, e partilha-a pessoalmente, não por SMS.
- Quem sabe a palavra-passe pode escrever com qualquer nome. Não há verificação de identidade individual.
- Quem controla o computador do servidor controla o código que os outros recebem. Ou seja, os teus amigos confiam em ti.
- Não há sigilo futuro: se a palavra-passe for descoberta, todo o histórico guardado pode ser lido. Para mudar, usem uma palavra-passe nova.
- Para apagar o histórico e os ficheiros, para o servidor e apaga a pasta `data/` (mantém `ca.pem` e `ca-key.pem`, senão todos têm de reinstalar o certificado).
