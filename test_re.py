import re

# Eksempel verdier for dest_ip og dest_port
dest_ip = '43.153.0.79'
dest_port = '55164'

# Netstat utdata
netstat_output = """
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      62697/sshd: /usr/sb
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      62719/systemd-resol
tcp        0      0 127.0.0.1:1883          0.0.0.0:*               LISTEN      62702/mosquitto
tcp        0      0 0.0.0.0:8000            0.0.0.0:*               LISTEN      62738/python3
tcp        0      0 192.168.41.101:22       192.168.41.83:49826     ESTABLISHED 54868/sshd: roy [pr
tcp        0      0 192.168.41.101:22       43.153.0.79:55164       ESTABLISHED 65524/sshd: freehci
tcp6       0      0 :::22                   :::*                    LISTEN      62697/sshd: /usr/sb
tcp6       0      0 ::1:1883                :::*                    LISTEN      62702/mosquitto
udp        0      0 127.0.0.53:53           0.0.0.0:*                           62719/systemd-resol
udp        0      0 192.168.41.101:68       0.0.0.0:*                           62714/systemd-netwo
raw6       0      0 :::58                   :::*                    7           62714/systemd-netwo
"""

# Kompilere regex-mønsteret med f-streng
ssh_port_regex = re.compile(
    fr'(?P<local_ip>\d{{1,3}}\.\d{{1,3}}\.\d{{1,3}}\.\d{{1,3}}):(?P<local_port>\d+)\s+'
    fr'(?P<foreign_ip>{re.escape(dest_ip)}):(?P<foreign_port>{re.escape(dest_port)})\s+'
)

# Søke i netstat utdata
matches = ssh_port_regex.finditer(netstat_output)

for match in matches:
    print("Match found:")
    print(f"Local IP: {match.group('local_ip')}")
    print(f"Local Port: {match.group('local_port')}")
    print(f"Foreign IP: {match.group('foreign_ip')}")
    print(f"Foreign Port: {match.group('foreign_port')}")
