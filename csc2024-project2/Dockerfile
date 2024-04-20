FROM ubuntu:latest

# Update the package lists
RUN apt-get update

# Install any necessary packages or dependencies
RUN apt-get install -y \
    git \
    curl \
    wget \
    vim \
    nano \
    python3 \
    g++ \
    net-tools \
    iputils-ping \
    iproute2 \
    make \
    cmake \
    gcc \
    build-essential \
    libssl-dev \
    libnetfilter-queue-dev \
    tcpdump

RUN apt-get clean


# Set up any environment variables
ENV PATH="/usr/local/bin:${PATH}"

# Copy files or directories into the container
COPY . /home

# Set the working directory
WORKDIR /home

# Specify the command to run when the container starts
CMD ["/bin/bash"]