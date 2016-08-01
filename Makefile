
all: build

deps/libuv:
	git clone --depth 1 https://github.com/libuv/libuv deps/libuv

build/gyp:
	git clone --depth 1 https://chromium.googlesource.com/external/gyp build/gyp

out/Makefile: deps/libuv build/gyp
	build/gyp/gyp -Duv_library=static_library --depth=$(PWD) --generator-output=$(PWD)/out -Goutput_dir=$(PWD)/out -f make build.gyp

build: out/Makefile
	$(MAKE) -C out

clean:
	rm -rf out

distclean:
	rm -rf build deps out

.PHONY: clean distclean
