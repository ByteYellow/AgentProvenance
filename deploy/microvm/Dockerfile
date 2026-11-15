FROM ubuntu@sha256:4fbb8e6a8395de5a7550b33509421a2bafbc0aab6c06ba2cef9ebffbc7092d90
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    systemd-sysv systemd-resolved systemd-timesyncd openssh-server python3 \
    ca-certificates iproute2 util-linux && \
    rm -rf /var/lib/apt/lists/* /etc/ssh/ssh_host_* && \
    mkdir -p /etc/agentprov-guest /var/lib/agentprov-guest /usr/local/libexec && \
    chmod 0700 /etc/agentprov-guest /var/lib/agentprov-guest && \
    truncate -s 0 /etc/machine-id && rm -f /var/lib/dbus/machine-id
COPY agentprov /usr/local/bin/agentprov
COPY guest_service.py /usr/local/libexec/agentprov-guest
COPY agentprov-guest.service /etc/systemd/system/agentprov-guest.service
COPY guest.fstab /etc/fstab
COPY guest.network /etc/systemd/network/80-guest.network
COPY guest-sshd.conf /etc/ssh/sshd_config.d/20-agentprov.conf
RUN chmod 0755 /usr/local/bin/agentprov /usr/local/libexec/agentprov-guest && \
    systemctl enable agentprov-guest.service systemd-networkd.service ssh.service && \
    systemctl disable ssh.socket && \
    mkdir -p /etc/systemd/system/ssh.service.d && \
    printf '[Unit]\nRequiresMountsFor=/etc/agentprov-guest\nConditionPathExists=/etc/agentprov-guest/ssh_host_ed25519_key\n' > /etc/systemd/system/ssh.service.d/guest.conf && \
    dpkg-query -W > /usr/share/agentprov-guest-packages.txt
CMD ["/sbin/init"]
