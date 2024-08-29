FIREWALL PARA UBUNTU SERVER

Está funcionando 100%, mais estou melhorando cada vez mais, na medida do possível.

Principais dúvidas:

O iptables protege contra vulnerabilidades do kernel?

Resposta: Não, o iptables não protege você de vulnerabilidades do kernel. Na verdade, o iptables também pode se tornar um vetor de ataque.

Existem outros lugares onde vulnerabilidades exploráveis ​​podem ocorrer:

O driver de rede: http://www.cvedetails.com/cve/CVE-2009-1389/

O próprio daemon SSH: http://www.openssh.com/security.html

Se você tiver sshd configurado com senhas fracas e alguém conseguir fazer força bruta, então exploits de escalonamento de privilégios locais podem ser tentados. O firewall normalmente não consegue capturar esse tipo de ataque, pois ele explora uma vulnerabilidade do aplicativo.

A melhor maneira de se proteger contra isso é tomando medidas preventivas, como não usar senhas fracas, não expor o host à Internet, a menos que seja necessário, manter-se atualizado aplicando patches de software, mudar a porta do ssh, instalar o Fail2Ban, etc.





