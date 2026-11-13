# Test SSH Vulnerable Server untuk ProbeX
# Docker-based, isolated, authorized CTF lab only

FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    openssh-server \
    && mkdir /var/run/sshd \
    && apt-get clean

# Non-root user dengan password lemah (cocok wordlist passwords.txt)
RUN useradd -m -s /bin/bash admin && echo 'admin:password123' | chpasswd
RUN useradd -m -s /bin/bash user && echo 'user:123456' | chpasswd
RUN echo 'root:toor' | chpasswd
RUN useradd -m -s /bin/bash ctf && echo 'ctf:ctf123' | chpasswd

# Flag file untuk tes --GET flag
RUN echo "FLAG{ssh_bruteforce_success}" > /flag.txt && chmod 644 /flag.txt

# Konfigurasi SSH: izinkan password auth + root login (sengaja rentan)
RUN sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config \
    && sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config \
    && sed -i 's/#PubkeyAuthentication yes/PubkeyAuthentication yes/' /etc/ssh/sshd_config

EXPOSE 2222

CMD ["/usr/sbin/sshd", "-D", "-p", "2222"]
