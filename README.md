# TLS Proxy

This is an event-based TLS proxy server inspired by nginx. It is based on `epoll()` and so is currently Linux-only, and I currently don't plan to extend it to similar platforms that provide similar interfaces. I may possibly change my mind.

## Compiling

### Dependencies:

- OpenSSL 3.x
- libcyaml
- Doxygen
- [Verstable](https://github.com/JacksonAllan/Verstable) (Included)
  - `src/verstable.h` is from commit https://github.com/JacksonAllan/Verstable/commit/dd83033fb72736a1d2332e43b84b7794b5d19635

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
- [ ] Optimize connection ctx for memory usage.
- [ ] Add a small proxy context that can be used to track the state of both sockets, and close one if the other socket closes.
- [ ] Work out if I need timeouts, and what for. If so, implement them.
- [ ] Separate functionality into master and worker processes.
- [ ] Implement shared memory for TLS connection caches and config updates.
- [ ] Implement signal handlers for online config update, graceful shutdown, etc.
- [ ] Implement privilege dropping, privsep, and chroot.
