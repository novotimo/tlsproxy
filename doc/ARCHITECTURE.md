# TLS Proxy Architecture

## Introduction

This TLS proxy is a small project I'm doing to practice software design, with its architecture strongly influenced by nginx's really nice event-based architecture. It's pretty much just stunnel, but implemented on an epoll-based event loop, so it's way over 10x faster while still being much simpler than nginx.

The intended audience is devops and sysadmins who want to have a TLS terminator that's quite easy on resources, and will be a first class citizen in Docker when used to protect microservices, though it can handle massive concurrency, matching `nginx`'s performance at around 300 handshakes per second per worker process on my CPU (an AMD Ryzen 7 5800X) while using negligible RAM.

## Definitions

- **Client**: Refers to the program connecting over a network via TLS to the TLS Proxy.
- **(Backend) Server**: Refers to the program that the TLS proxy connects to in plaintext upon request of the client.

## Requirements

### Functional

1. This program must listen for TLS connections on a port, and whenever it receives one make a connection to a backend server, forwarding the decrypted packets to it.
2. The backend server must see the connection as plaintext.
3. The client must see the connection as TLS-tunneled.
4. The program must be configurable with a configuration file.
5. The program must be runnable as a daemon with priv dropping and chroot.
6. The program must run on modern Linux machines.

### Non-functional

1. This program must support the most up-to-date security measures in TLS (such as MLKEM-ed25519 hybrid TLS groups).
2. This program must handle more than 80% of the connections per second that `stunnel` handles.
3. It should perform error checking and be able to recover from most errors.

## Constraints

1. The deadline is the 14th of December, 2025.
2. The developer only knows C, C++, Python, and Haskell to a reasonable enough extent.
3. The developer is most familiar with OpenSSL, which is a C library.

## Architecture

### System context

![System Context Diagram for TLS Proxy.png](System Context diagram for TLS Proxy.drawio.png)

### Component diagram

![Component Diagram of the TLS Proxy.png](Component diagram for TLS Proxy.drawio.png)

## Design decisions

### Programming language

This project will be completed in C, mainly for performance reasons. If this project is aiming to be faster than stunnel, it has to avail itself of all advantages possible, especially the low-hanging fruit such as this. C was also chosen over many interpreted languages due to its low-level epoll interface, and while I could have used C++ for this, C is frankly much simpler to optimize when the C++ compilers are considered, and this project has a 2 week deadline.

### Process/Concurrency model

This project's process and concurrency model is based heavily on nginx's, as is virtually every server hoping for both HA and performance, such as Envoy Proxy. This process model has a main process which initializes the shared memory, listens on the socket, drops privileges, and creates the workers, which are child processes. Then, it just waits for signals which it can use to control the workers. The workers each have a central event loop, in which each proxy connection uses the proxy state machine. The event loop will also handle timeouts in a similar way as nginx, which does them quite intelligently: using red-black trees to store timeouts so that the nearest one is always available in O(log(n)) time.

### High Availability

**UNDECIDED**. How can I make this live forever? There are a few things that `nginx` does that hint to me that malloc fragmentation would give this program a bit of grief, such as use custom slab and pool allocators. I think those are also for cache optimization, though.

### Performance

There are a few considerations for speed. First, this software is optimized for memory footprint. It's predicted that the main performance bottleneck will be OpenSSL cryptography calculations, and there's not much we can do to change this. The main goal would be to reduce overhead so that we're as close to OpenSSL speed as possible. Where possible we do this, though we can't use a copy-free architecture since we can't exactly encrypt in-place.

### Configuration

This will just use a simple YAML configuration file for now. As of now not much configurability is to be implemented, due to time constraints. The configuration will be as so:


```yaml
## The number of worker processes, should be the same as your number
## of cores.
nworkers: 16
logfile: tlsproxy.log
## Log levels are: FATAL ERROR WARN INFO DEBUG
loglevel: DEBUG

## Connection details of the backend server
target-ip: 127.0.0.1
#target-ip: 10.255.255.1
target-port: 8080

## If we can't connect to the server by this time, drop the connection
connect-timeout: 5000

## The proxy will accept connections on <listen-ip>:<listen-port>
## 0.0.0.0 means listen on every interface
listen-ip: 0.0.0.0
listen-port: 8443

## The certificate chain offered to clients
cacerts:
- cacert.pem
- intcert.pem
servcert: servcert.pem
servkey: servkey.pem
#servkeypass: test

## Alternatively, provide all certs (including server cert) in a single file:
# cert-chain: chain.pem
# servkey: servkey.pem
# servkeypass: test
## cacerts and servcert can't be used together with cert-chain.

## If we implement mTLS:
# trusted-certs:
# - clientroot.pem
## In this example, only the root is provided. If your client doesn't send the
## chain certs, you will need to include the intermediate certs here.
## Also, if the client cert is self-signed or you don't have its chain, just
## put it in here.
```

### Documentation

The documentation is done in Doxygen, and a CI step to build this and host it on GitHub Pages is planned.

### Testing

Unit testing is done with CMocka, though the tests need updating as the software is in constant development.


## General Code model

### Main

In the parent process, this will read the config files, initialize shared memory, drop privileges, and start the worker processes, then wait for signals. In the worker processes, this listens on the proxy sockets with SO_REUSEPORT, and for each connection received creates a new proxy context, and every new event on the file descriptors will be handled by the proxy state machine, the state of which is the aforementioned proxy context.

### Events

Events are the data we store a pointer to in epoll. They're distinguished by their event ID, of which we have `EV_LISTEN` and `EV_PROXY`. The event dispatcher in `src/event.c` checks the event ID and dispatches to `handle_accept()` or `handle_proxy()` based on that.

### Proxy

In general, the proxy is a state machine created when a connection is accepted on the listen socket. The states are:
- `PS_CLIENT_CONNECTED`
- `PS_SERVER_CONNECTING`
- `PS_READY`
- `PS_SERVER_DISCONNECTED`
- `PS_CLIENT_DISCONNECTED`

The proxy will be created once the client fully finishes its TLS handshake and is fully connected and authenticated. So, the first state is "Client connected". When this happens, we start trying to connect to the server and set the state to "Server connecting". Once it's connected, we move to "Ready".

In the "Ready" state, we forward the data received on both sockets to the other, after encryption/decryption. When one side disconnects, we move to the respective state, as the situations are different: if the server disconnects, we still need to do a graceful TLS shutdown. If the client disconnects, we can just send a connection reset to the server.

The important decision regarding the proxy context (`proxy_t` in `inc/proxy.h`) was to use the same context for both sockets in the proxy pair. This begs the question, how do you tell events apart? When using `epoll_wait`, you get back an arbitrary 64-bit value, either an fd, or a pointer to something. We want the pointer to be towards the same data, but we want to tell the pointers apart without needing the other one and without wasting too much space. So, we've chosen to tag the pointers: malloc aligns to an 8-byte boundary, and so the last 3 bits of the pointer can be used for other things. We use the last bit of the pointer as a tag: `uint8_t tag = (uintptr_t)event & 0x1`. If this tag is 1, this is the client socket. If it's 0, this is the server socket. We strip the tag as soon as possible so that we don't dereference the proxy pointer misaligned by one byte.


### Listener

The listener context just contains the listen socket and the peer address, used for connecting new sockets to the remote host once we accept a new connection. Basically, when a listener accepts a connection, it starts a new pending connection to the peer address. This is stored here so that we can easily support listening on multiple sockets and forwarding to different backend servers. Used with `SO_REUSEPORT`, this could also achieve load balancing: create two listen sockets both on the same port, but pointing to different backends, and the kernel will load balance for us.


## Log messages

Logging will output in key-value format to a simple log file. The main aim for the logger is to allow easy integration with any log analysis or monitoring system, as I imagine this to be important for many users. The log messages can be treated as audit events, each having an event type. For now, the logger will chose to not send incomplete log messages, but eventually there will be a system to truncate log messages while keeping the key-value format parseable. The schema is as so:

### Base schema

All other schemas will inherit from this. Each log event has:
- `timestamp`: This is in RFC 3339 format.
- `service`: "tlsproxy", used to identify this product.
- `process_type`: "worker" or "master", depending on whether this is an event from the master process or a worker process.
- `pid`: The process id.
- `level`: The log level. This is one of FATAL, ERROR, WARN, INFO, or DEBUG, where FATAL is the lowest and DEBUG is the highest.
- `event`: The specific event name will be one of the events described after this.

An example base message is `timestamp=2025-12-13T23:33:11+1100 service=tlsproxy process_type=master pid=8264 level=INFO event=handshake`.


### Startup Event

This is sent by the master process and will contain (over the base schema):
- `event`: "startup".
- `argv`: The arguments given during process start.
- `version`: The version of the software loaded.

### Worker Event

This is sent by the master process when it creates workers:
- `event`: "worker"
- `worker_state`: "dead", "spawned"
- `worker_id`: The internal ID of the worker. 
- `worker_pid`: The PID of the worker.

### Config Loaded Event

This is called whenever the configuration file is (re)loaded. It will contain the major config info:
- `event`: "config_loaded".
- `nworkers`: The number of workers to create.
- `certchain`: (Optional) The cert chain file.
- `cacerts`: (Optional) A list of CA certificate files separated by ':'.
- `servcert`: (Optional) The server certificate file.
- `servkey`: The server certificate file.

### Cert Loaded Event

This is called whenever we load a certificate, and is useful mainly in the case of hot reloading, and verifying that the hot reload worked:
- `event`: "cert_loaded".
- `cert_role`: "leaf", "server\_ca", or "client\_ca".
- `cert_fingerprint`: The certificate fingerprint.
- `cert_notbefore`: The date at which the cert becomes active.
- `cert_notafter`: The date at which the cert expires.
- `cert_subject`: The subject of the certificate.
- `cert_issuer`: The issuer of the certificate.

### System Error Events

These are errors that occur during startup and aren't related to a proxy, and can be sent from both master and worker processes.
- `event`: "system\_error".
- `error_msg`: The message provided by TLS Proxy.
- `error_desc`: The human-readable error description for the error code. If it's a libc error, this is `strerror(errno)`. If it's an OpenSSL error, this contains the OpenSSL error queue, with all newlines escaped so that it can be un-flattened for pretty printing. OpenSSL errors are included in system errors.

### Signal Received Events

This can be sent from either a worker or master process. It shows that a signal was received.

- `event`: "signal\_received"
- `signal_num`: The signal number as an integer.
- `signal_string`: The string representing the signal (from `strsignal()`)
- `recvd_from`: The PID of the program that sent this signal.

### Proxy Events

- `event`: "proxy"
- `subevent`: "client\_connect", "server\_connect", "client\_disconnect", "server\_disconnect"
- `client_ip`: Client's remote IP address.
- `client_port`: Client's remote port.
- `listen_ip`: The address we're listening on.
- `listen_port`: The listen port on which we accepted the connection.
- `server_ip`: Server's remote IP address.
- `server_port`: The port of the server.
- `error_msg`: The message provided by TLS Proxy (if this is a disconnect event).
- `error_desc`: (Optional) The human-readable error description for the error code (if this is an ioerror). If it's a libc error, this is `strerror(errno)`. If it's an OpenSSL error, this contains the OpenSSL error queue, with all newlines escaped so that it can be un-flattened for pretty printing. If we close due to the other socket closing, this field won't be attached.

### Auth Events

These sub events are logged separately because of how OpenSSL works.

- `event`: "auth"
- `subevent`: "handshake" or "mtls"
- `outcome`: "granted", "denied", or "failed". If it's "denied" then there was a security problem, if it's "failed" there was a system problem.
- `client_ip`: Client's remote IP address.
- `client_port`: Client's remote port.
- `listen_ip`: The address we're listening on.
- `listen_port`: The listen port on which we accepted the connection.
- `error_msg`: The message provided by TLS Proxy.
- `error_desc`: The human-readable error description for the error code. If it's a libc error, this is `strerror(errno)`. If it's an OpenSSL error, this contains the OpenSSL error queue, with all newlines escaped so that it can be un-flattened for pretty printing.
- `ciphersuite`: (If it's a successful handshake) The ciphersuite chosen.
- `client_cert_fingerprint`: (For mtls) The SHA256 fingerprint of the client certificate.
- `client_cert_subject`: (For mtls) The subject of the client certificate.
- `client_cert_issuer`: (For mtls) The issuer of the client certificate.
