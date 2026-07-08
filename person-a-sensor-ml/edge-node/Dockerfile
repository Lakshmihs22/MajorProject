FROM python:3.11-slim

RUN for f in /etc/apt/sources.list /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources; do \
        [ -f "$f" ] && sed -i 's#http://deb.debian.org#https://deb.debian.org#g; s#http://security.debian.org#https://security.debian.org#g' "$f"; \
    done; \
    echo 'Acquire::Retries "5";' > /etc/apt/apt.conf.d/99-retries && \
    apt-get update && apt-get install -y --no-install-recommends \
    openssh-server \
    net-tools \
    iputils-ping \
    && rm -rf /var/lib/apt/lists/*

# Minimal placeholder service so the node responds to port scans / brute force.
# Person A: replace with whatever combination of a weak SSH config and a
# simple HTTP service best simulates a realistic edge device.
RUN mkdir -p /run/sshd

EXPOSE 22 80

CMD ["/usr/sbin/sshd", "-D"]
