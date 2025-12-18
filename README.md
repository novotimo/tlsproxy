# TLS Proxy README

TLS termination proxy made to handle (tens of) thousands of concurrent connections. Has comparable* performance to nginx, at a tiny fraction of the attack surface!

(*) It's faster than nginx in almost everything but HTTPS reverse proxying, since nginx has some very nice connection pooling and socket reuse methods exclusive to HTTP that they use. If you want to proxy HTTP to HTTPS, use nginx reverse proxy.

## Speed

Here are some apib benchmarks done against nginx, see the `benchmark/` folder for details.

Left (yellow) is nginx, total of 9 million (9105624) requests over 5 minutes, and right (green) is tlsproxy, total of 18 million (18414469) requests over 5 minutes:
<img width="3346" height="1577" alt="image" src="https://github.com/user-attachments/assets/27997d0a-2f3a-4f73-86f1-d9236285ab37" />

Send/receive bandwidth for nginx: 13.66Mbit/s send, 197.52Mbit/s receive.
Send/receive bandwidth for tlsproxy: 27.66Mbit/s send, 399.45Mbit/s receive.

Memory usage for nginx: 34MB + 700MB cache, memory usage for tlsproxy was 69MB.

## Try it out

### Full demo

All you need to do is download the `example-docker/` folder, cd into it, and run `docker compose -f compose.yml up`, and you should get a TLS proxy which listens on port 443 and forwards HTTPS requests over a docker network to an nginx HTTP server. Try pointing your browser to https://localhost.

### Demo with your own plain server

You can try this out as a docker image. First get the docker image:

```
$ docker pull novotimo/tlsproxy:latest
```

Then, get your config and certs. An example config and certs can be found in `example-docker/config/`. Point the `target-ip` and `target-port` config options to your plain server, and set the `listen-port` to whatever you want. Then, run:
```
$ docker run --name tlsproxy --volume ${PWD}/example-docker/config/:/etc/tlsproxy --expose=443 novotimo/tlsproxy:latest
```

## Compiling

### Dependencies:

- OpenSSL 3.x
- libcyaml
- Doxygen (optional, for docs)
- [Verstable](https://github.com/JacksonAllan/Verstable) (Included)
  - `src/verstable.h` is from commit https://github.com/JacksonAllan/Verstable/commit/dd83033fb72736a1d2332e43b84b7794b5d19635
- CMocka (optional, for tests)

To build this, you first need to install https://github.com/tlsa/libcyaml. This was built against `libcyaml` 1.4.2. Follow their instructions to install it first.

Next, install OpenSSL with your package manager. Which version is up to you, but if 3.5.x or higher is available, you get those sweet sweet PQC algorithms to use with TLS 1.3.

Optionally, you can install Doxygen to build the docs, but that's not strictly required.

Then, simply build with CMake:

```
cmake -B build
cmake --build build
```

This will build everything into the `build/` directory.

### Caveats

`libcyaml` doesn't use CMake so our `CMakeLists.txt` assumes it's installed under the `/usr/local` prefix. If it isn't, to build this you'll have to point the `IMPORTED_LOCATION` and `INTERFACE_INCLUDE_DIRECTORIES` of the `cyaml` library in `CMakeLists.txt` to your installed libs and includes.

## Usage

`./tlsproxy <config.yml>`

## Configuration

Please see the default configuration file in `example/default.yml`.


## Milestones/todo list

- [x] Spin up an epoll-driven echo server.
- [x] Add a connection context to hold the fd, queue buffers, and read and write callbacks.
- [x] Implement IO based on `connection_t` and handle their queue buffers.
- [x] Add a way to handle logging in a performant way, printing error messages where they occur but returning simple error codes that the program can deal with easily (not needing to pass error_txt parameters).
  - Looks like we're only logging errors.
- [x] Implement config file reading in YAML.
- [x] Make the buffer queue fill up a buffer until it's full rather than malloc a new one for each message.
- [x] Add TLS functionality to that connection context: add an OpenSSL context and make the handlers work differently depending on if the connection is TLS or not.
- [x] Optimize connection ctx for memory usage.
- [x] Add a small proxy context that can be used to track the state of both sockets, and close one if the other socket closes.
- [x] Work out if I need timeouts, and what for. If so, implement them.
- [x] Separate functionality into master and worker processes.
- [ ] Implement shared memory for TLS connection caches and config updates.
- [ ] Implement signal handlers for online config update, graceful shutdown, etc.
- [ ] Implement privilege dropping, privsep, and chroot.
