TARGET = nettool
ARCH = $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

BPF_SRCS = tcpstates.bpf.c tcprtt.bpf.c tcpconnlat.bpf.c udpbwth.bpf.c udpcongest.bpf.c sockredirect.bpf.c xdpforward.bpf.c
BPF_OBJS = $(addprefix build/,$(BPF_SRCS:.bpf.c=.bpf.o))
BPF_SKELS_TEMP = $(BPF_SRCS:.bpf.c=.skel.h)
BPF_SKELS = $(addprefix build/,$(BPF_SRCS:.bpf.c=.skel.h))
USER_OBJ = build/nettool.o
EXECUTABLE = bin/$(TARGET)

CLANG_FLAGS = -target bpf -D __BPF_TRACING__ -D__TARGET_ARCH_$(ARCH) -I/usr/include/$(shell uname -m)-linux-gnu -Wall -O2 -g
CC_FLAGS = -Wall -O2 -g -I.

all: $(EXECUTABLE) move_skeletons
.PHONY: all clean move_skeletons

$(EXECUTABLE): $(BPF_OBJS) $(USER_OBJ)
	@mkdir -p bin
	$(CC) -o $@ $(USER_OBJ) -lbpf -lelf -lz

build/%.o: %.c $(BPF_SKELS_TEMP)
	@mkdir -p build
	$(CC) $(CC_FLAGS) -c -o $@ $<

build/%.bpf.o: %.bpf.c vmlinux.h
	@mkdir -p build
	clang $(CLANG_FLAGS) -o $@ -c $<

%.skel.h: build/%.bpf.o
	bpftool gen skeleton $< > $@

move_skeletons: $(BPF_SKELS_TEMP)
	@mkdir -p build
	@mv $(BPF_SKELS_TEMP) build/

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

clean:
	- rm -rf build bin vmlinux.h $(BPF_SKELS_TEMP)

