# TLS Proxy

This is an event-based TLS proxy server inspired by nginx.

## Compiling

To build this, you first need to install https://github.com/tlsa/libcyaml. This was built against `libcyaml` 1.4.2. Follow their instructions to install it first.

Optionally, you can install Doxygen to build the docs, but 
Next, install Doxygen with 

Then, simply do this:

```
cmake -B build
cmake --build build
```

This will build everything into the `build/` directory.

### Caveats

`libcyaml` doesn't use CMake so we assume it's installed under the `/usr/local` prefix. If it isn't, to build this you'll have to point the `IMPORTED_LOCATION` and `INTERFACE_INCLUDE_DIRECTORIES` of the `cyaml` library in `CMakeLists.txt` to your installed libs and includes.

## Usage

`./tlsproxy <config.yml>`

## Configuration

Please see the default configuration file in `example/default.yml`.
