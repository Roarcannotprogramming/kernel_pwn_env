FROM debian:bookworm

COPY sources.list /etc/apt/sources.list

RUN rm -rf /etc/apt/sources.list.d/*

RUN apt update && \
    DEBIAN_FRONTEND=noninteractive apt install -y wget zstd curl git liburing-dev gdb qemu-system python3 python3-pip ipython3 tree procps musl musl-tools musl-dev libkeyutils-dev

RUN apt build-dep -y linux || apt install -f

RUN apt install -y libelf-dev libssl-dev bison flex bc libncurses-dev

RUN git clone https://github.com/pwndbg/pwndbg && \
    cd pwndbg && \
    ./setup.sh 

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

CMD ["/entrypoint.sh"]
# CMD ["tail", "-f", "/dev/null"]

