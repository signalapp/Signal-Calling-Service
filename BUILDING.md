# Building the Calling Server

## For Development & Debugging

    cargo run

You can specify a variety of command line arguments. See the [config.rs file](/src/config.rs) file for
more details or run:

    cargo run -- --help

A common example for debugging would be:

    cargo run -- --binding-ip 192.168.1.100 --ice-candidate-ip 192.168.1.100 --diagnostics-interval-secs 1

where ```--binding-ip``` sets the IP address that the servers will listen on and ```--ice-candidate-ip```
is the IP address that will accept media packets from clients. Use the IP addresses specific to your
environment. ```--diagnostics-interval-secs``` sets the metrics gathering interval, here to be every
second.

The configuration shown is for debugging and uses the internal http_server for testing, to which clients
can connect directly. Usually this is achieved through a TLS veneer such as [ngrok](https://ngrok.com/).

## For Running Tests

    cargo test

or

    cargo test --release

## For Release Builds and Performance Testing

Release builds and all performance testing should use the ```--release``` build option:

    cargo run --release

For best performance, the target CPU should also be specified. In this example, ```native``` is used
to instruct the compiler to optimize for the CPU that is performing the build itself:

    RUSTFLAGS="-C target-cpu=native" cargo run --release

## For Deployment

Signal uses the provided Dockerfile to build images for deployment. This uses a multi-stage process,
creating a builder image, a minimal image for delivery, and a runnable image for testing.

### Building the Docker Image

Images currently run on AWS EC2 instances supporting the Intel Skylake architecture. When building
the image, we can target that specific CPU (or choose any other that matches the platform where the
container will be run):

    docker build --build-arg rust_flags=-Ctarget-cpu=skylake -t signal-calling-server .

The ```build-arg``` can also be omitted to maintain maximum compatibility.

_Note: At the time of this writing, the skylake-avx512 target is not compatible with some dependencies._

### Deploying the Docker Image

The deployment is specific to the type of service or registry being used. For testing, the
image can be saved and copied somewhere for running. To save:

    docker save signal-calling-server:latest | gzip > signal-calling-server-latest.tar.gz

### Running the Docker Container

To run the container, the following docker command can be used:

    docker run -d --rm -p 8080:8080 -p 10000:10000/udp signal-calling-server:latest

- ```-d``` runs the container in detached mode (can be omitted for easier testing)
- ```--rm``` will clean up the container when it is stopped
- ```-p 8080:8080``` connects the TCP port 8080 to the same one on the host
- ```-p 10000:10000/udp``` connects the UDP port 10000 to the same one on the host

#### Configuration Options

Certain configuration options can be passed when running the container. Currently, any of the
following can be specified:
- ICE_CANDIDATE_IP
- SIGNALING_IP
- DIAGNOSTICS_INTERVAL_SECS

For example:

    docker run --rm -p 8080:8080 -p 10000:10000/udp \
        -e ICE_CANDIDATE_IP=192.168.1.100 \
        -e DIAGNOSTICS_INTERVAL_SECS=1 \
        signal-calling-server:latest

The host will listen on port 8080 for requests and publish 192.168.1.100:10000 to clients for media
access. Packets to that address will be routed to the running container.

### Binary Deployment

The docker file can also be used to obtain a binary file:

    docker build --build-arg rust_flags=-Ctarget-cpu=skylake -t signal-calling-server --target export-stage -o bin .

This will build the calling_server binary executable for Linux and copy it to the ./bin directory of
the host. The command will stop at the export-stage and not create the runnable docker image.
