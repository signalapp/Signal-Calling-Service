# Building

## For Development & Debugging

    cargo run --bin calling_backend

or

    cargo run --bin calling_frontend

You must specify a variety of command line arguments. See [backend config.rs file](/backend/src/config.rs) or
[frontend config.rs file](/frontend/src/config.rs) for more details or run either with the `--help` option.

## Debugging with the Backend

An example for debugging the backend would be:

    cargo run --bin calling_backend -- --binding-ip 192.168.1.100 --ice-candidate-ip 192.168.1.100 --diagnostics-interval-secs 1

where ```--binding-ip``` sets the IP address that the backend will listen on and ```--ice-candidate-ip```
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

    cargo run --bin calling_backend --release

For best performance, the target CPU should also be specified. In this example, ```native``` is used
to instruct the compiler to optimize for the CPU that is performing the build itself:

    RUSTFLAGS="-C target-cpu=native" cargo run --bin calling_backend --release

## For Deployment

Signal uses Docker files to build images for deployment. This uses a multi-stage process,
creating a stage for building and a runnable image.

### Building the Docker Images

When building the images, we can target that specific CPU (or choose any other that matches the platform where the
container will be run, such as the Intel Skylake architecture):

    docker build -f backend/Dockerfile --build-arg rust_flags=-Ctarget-cpu=skylake -t signal-calling-backend .

or

    docker build -f frontend/Dockerfile --build-arg rust_flags=-Ctarget-cpu=skylake -t signal-calling-frontend .

The ```build-arg``` can also be omitted to maintain maximum compatibility.

_Note: At the time of this writing, the skylake-avx512 target is not compatible with some dependencies._
