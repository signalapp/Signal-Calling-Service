# Calling Service load generator

This provides a synthetic test client in order to generate load and for
testing congestion control scenarios.

# Usage instruction

Start a backend instance with:

`cargo run --bin calling_backend -- --signaling-port 8080 --diagnostics-interval-secs 10 --max-clients-per-call 20`

Now you can start load test instances with:

SCENARIO=X `cargo run --bin load_test http://localhost:8080 2:0:00:0:0:0`

Where X is one of :

unlimited --- a load test: all clients accept all videos, no bandwidth
limits

pipunpip --- congestion control test: one client runs in PiP for 15 seconds,
then unpip for 30 seconds, fixed 2000 kbps bandwidth limit; other clients
request no video

pipunpip_bwlimit --- like pipunpip, but the bandwidth limit is 1500 kbps
during the first 5 seconds of each unpip cycle

periodic --- one client requests all video, others request none; bandwidth
limit switches between 4 Mbps for 20 seconds, 1 Mbps for 10 seconds

Once two test instances are connected, the one with the lowest demux ID will
start outputing statistics in csv.

Under all scenarios, all clients will send a simulated audio packet with 300
payload bytes every 60 ms, and three layers of simulated 30fps video at
100/300/600 kbps. Acks are sent once ever 100 ms, height requests once every
second (more often as clients join).
