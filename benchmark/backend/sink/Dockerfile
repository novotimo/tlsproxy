# Static binary on scratch, so the sink's own cgroup memory is unambiguous:
# whatever the container accounts for is connection state, not a runtime.
FROM alpine:3.23 AS build
RUN apk add --no-cache build-base
WORKDIR /src
COPY sink.c .
RUN gcc -O2 -Wall -Wextra -Werror -static -o sink sink.c

FROM scratch
COPY --from=build /src/sink /sink
ENTRYPOINT ["/sink"]
