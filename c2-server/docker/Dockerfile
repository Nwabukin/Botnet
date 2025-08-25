# Multi-stage Dockerfile for C2 Server
# Optimized for security, performance, and research environments

# ================================
# Build Stage 1: Base Build Environment
# ================================
FROM ubuntu:22.04 AS build-base

# Set environment variables for non-interactive installation
ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=UTC

# Install build dependencies and tools
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    ninja-build \
    pkg-config \
    git \
    wget \
    curl \
    unzip \
    software-properties-common \
    && rm -rf /var/lib/apt/lists/*

# Install modern C++ compiler
RUN add-apt-repository ppa:ubuntu-toolchain-r/test -y && \
    apt-get update && \
    apt-get install -y gcc-12 g++-12 && \
    update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-12 60 --slave /usr/bin/g++ g++ /usr/bin/g++-12 && \
    rm -rf /var/lib/apt/lists/*

# ================================
# Build Stage 2: Dependencies
# ================================
FROM build-base AS dependencies

WORKDIR /deps

# Install Boost libraries
RUN wget https://boostorg.jfrog.io/artifactory/main/release/1.82.0/source/boost_1_82_0.tar.gz && \
    tar -xzf boost_1_82_0.tar.gz && \
    cd boost_1_82_0 && \
    ./bootstrap.sh --with-libraries=system,thread,chrono,regex,filesystem,program_options && \
    ./b2 -j$(nproc) variant=release link=static threading=multi && \
    ./b2 install && \
    cd .. && rm -rf boost_1_82_0*

# Install OpenSSL
RUN wget https://www.openssl.org/source/openssl-3.1.0.tar.gz && \
    tar -xzf openssl-3.1.0.tar.gz && \
    cd openssl-3.1.0 && \
    ./Configure linux-x86_64 --prefix=/usr/local --openssldir=/usr/local/ssl && \
    make -j$(nproc) && \
    make install && \
    cd .. && rm -rf openssl-3.1.0*

# Install nlohmann/json
RUN git clone https://github.com/nlohmann/json.git && \
    cd json && \
    mkdir build && cd build && \
    cmake -DJSON_BuildTests=OFF .. && \
    make -j$(nproc) install && \
    cd ../.. && rm -rf json

# Install WebSocket++
RUN git clone https://github.com/zaphoyd/websocketpp.git && \
    cd websocketpp && \
    mkdir build && cd build && \
    cmake .. && \
    make install && \
    cd ../.. && rm -rf websocketpp

# Install libpqxx for PostgreSQL
RUN apt-get update && apt-get install -y libpq-dev && \
    git clone https://github.com/jtv/libpqxx.git && \
    cd libpqxx && \
    mkdir build && cd build && \
    cmake -DSKIP_BUILD_TEST=ON .. && \
    make -j$(nproc) install && \
    cd ../.. && rm -rf libpqxx && \
    rm -rf /var/lib/apt/lists/*

# Install Redis C++ client
RUN git clone https://github.com/sewenew/redis-plus-plus.git && \
    cd redis-plus-plus && \
    mkdir build && cd build && \
    cmake -DREDIS_PLUS_PLUS_CXX_STANDARD=17 .. && \
    make -j$(nproc) install && \
    cd ../.. && rm -rf redis-plus-plus

# Install Prometheus C++ client
RUN git clone https://github.com/jupp0r/prometheus-cpp.git && \
    cd prometheus-cpp && \
    git submodule init && git submodule update && \
    mkdir build && cd build && \
    cmake -DENABLE_TESTING=OFF .. && \
    make -j$(nproc) install && \
    cd ../.. && rm -rf prometheus-cpp

# ================================
# Build Stage 3: Application Build
# ================================
FROM dependencies AS app-build

WORKDIR /app

# Copy source code
COPY c2-server/src/ ./src/
COPY common/ ./common/
COPY c2-server/CMakeLists.txt ./
COPY CMakeLists.txt ./root_CMakeLists.txt

# Create build directory and compile
RUN mkdir build && cd build && \
    cmake -DCMAKE_BUILD_TYPE=Release \
          -DCMAKE_CXX_STANDARD=20 \
          -DENABLE_OPTIMIZATION=ON \
          -DENABLE_SECURITY_HARDENING=ON \
          -DRESEARCH_MODE=ON \
          .. && \
    make -j$(nproc)

# ================================
# Build Stage 4: Web Dashboard Build
# ================================
FROM node:18-alpine AS dashboard-build

WORKDIR /dashboard

# Copy web dashboard source
COPY c2-server/web-dashboard/ ./

# Install dependencies and build
RUN npm install && \
    npm run build

# ================================
# Production Stage: Runtime Environment
# ================================
FROM ubuntu:22.04 AS production

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive
ENV C2_MODE=RESEARCH
ENV C2_LOG_LEVEL=INFO
ENV C2_BIND_ADDRESS=0.0.0.0
ENV C2_HTTP_PORT=8080
ENV C2_HTTPS_PORT=8443
ENV C2_WEBSOCKET_PORT=8081
ENV C2_DATABASE_URL=postgresql://botnet:research@postgres:5432/botnet_research
ENV C2_REDIS_URL=redis://redis:6379
ENV RESEARCH_MODE=true
ENV RESEARCH_SESSION_ID=""

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    curl \
    wget \
    netcat \
    postgresql-client \
    redis-tools \
    supervisor \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for security
RUN groupadd -r c2server && \
    useradd -r -g c2server -d /home/c2server -s /bin/bash c2server && \
    mkdir -p /home/c2server && \
    chown -R c2server:c2server /home/c2server

# Create application directories
RUN mkdir -p /app/bin \
             /app/web \
             /app/data \
             /app/logs \
             /app/config \
             /app/certs \
             /app/scripts && \
    chown -R c2server:c2server /app

# Copy built application
COPY --from=app-build /app/build/c2_server /app/bin/
COPY --from=dashboard-build /dashboard/dist/ /app/web/

# Copy configuration files
COPY c2-server/docker/configs/ /app/config/
COPY c2-server/scripts/ /app/scripts/

# Copy SSL certificates (self-signed for research)
COPY c2-server/docker/certs/ /app/certs/

# Set up supervisor configuration
COPY c2-server/docker/supervisor/ /etc/supervisor/conf.d/

# Set permissions
RUN chown -R c2server:c2server /app && \
    chmod +x /app/bin/c2_server && \
    chmod +x /app/scripts/*.sh

# Health check script
COPY c2-server/docker/healthcheck.sh /usr/local/bin/healthcheck.sh
RUN chmod +x /usr/local/bin/healthcheck.sh

# Expose ports
EXPOSE 8080 8443 8081 9090

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD /usr/local/bin/healthcheck.sh

# Switch to non-root user
USER c2server

# Set working directory
WORKDIR /app

# Volume mounts for persistent data
VOLUME ["/app/data", "/app/logs", "/app/config"]

# Entry point script
COPY c2-server/docker/entrypoint.sh /app/entrypoint.sh
USER root
RUN chmod +x /app/entrypoint.sh
USER c2server

ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["c2_server"]

# ================================
# Research Mode Stage (Optional)
# ================================
FROM production AS research

# Additional tools for research environment
USER root

RUN apt-get update && apt-get install -y \
    tcpdump \
    wireshark-common \
    tshark \
    nmap \
    netstat-nat \
    htop \
    iotop \
    strace \
    gdb \
    valgrind \
    && rm -rf /var/lib/apt/lists/*

# Install research monitoring tools
COPY c2-server/docker/research-tools/ /app/research-tools/
RUN chown -R c2server:c2server /app/research-tools && \
    chmod +x /app/research-tools/*.sh

# Research mode configuration
ENV RESEARCH_MODE=true
ENV RESEARCH_LOGGING=verbose
ENV RESEARCH_MONITORING=enabled
ENV ETHICAL_CONTROLS=strict

USER c2server

# Research-specific entry point
COPY c2-server/docker/research-entrypoint.sh /app/research-entrypoint.sh
USER root
RUN chmod +x /app/research-entrypoint.sh
USER c2server

ENTRYPOINT ["/app/research-entrypoint.sh"]
