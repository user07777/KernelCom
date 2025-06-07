# KernelCom
⚠️ **Disclaimer**

Este projeto é uma prova de conceito com finalidade puramente educacional.  
Ele não deve ser executado, compilado ou adaptado para uso em qualquer sistema real.  
Todas as referências a funções, offsets e estruturas do Windows foram modificadas, omitidas ou ofuscadas propositalmente para evitar uso indevido.

Este projeto:

- Não contém payloads funcionais
- Não implementa nenhum exploit
- Não contorna proteção de segurança em ambientes reais
- NÃO deve ser usado para criar cheats, bypasses ou rootkits

---

## Objetivo

Explorar conceitos de:

- Espaço de sessão (`Session Space`) no kernel do Windows
- Anexação de contexto via `KeStackAttachProcess`
- Estruturas internas como `TEB`, `TLS slots`, `PsLoadedModuleList`
- Técnicas de interceptação de chamadas em contexto controlado

---

## Aviso legal

Qualquer uso indevido ou adaptação deste código é de responsabilidade exclusiva do indivíduo.  
Você é o responsável por garantir que seu uso esteja de acordo com leis locais, políticas da Microsoft e os termos de serviço de qualquer plataforma utilizada.

![image](https://github.com/user-attachments/assets/3661f76d-8326-4808-9190-dfc0a1461762)
