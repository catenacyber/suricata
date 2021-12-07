FROM gcr.io/oss-fuzz-base/base-builder-rust
RUN apt-get update && apt-get install -y build-essential libpcap-dev   \
                    libyaml-0-2 libyaml-dev pkg-config zlib1g zlib1g-dev \
                    make libmagic-dev libjansson libjansson-dev libpcre2-dev \
# autoconf automake libtool python flex bison cmake tshark

RUN cargo install --force cbindgen

COPY . $SRC/suricata

ADD https://rules.emergingthreats.net/open/suricata/emerging.rules.zip emerging.rules.zip
RUN git clone --depth=1 https://github.com/catenacyber/fuzzpcap
RUN git clone --depth 1 https://github.com/OISF/libhtp.git libhtp
RUN git clone --depth 1 https://github.com/OISF/suricata-verify suricata-verify

WORKDIR $SRC/suricata
COPY ./.clusterfuzzlite/build.sh $SRC/
