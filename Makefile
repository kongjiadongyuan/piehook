CXX := g++
CC := gcc
DEPFLAGS := -MM
CFLAGS := -wall -g
.PHONY:all clean

all:
	$(MAKE) -C ./kernel_module
	$(MAKE) -C ./cJSON
	$(MAKE) -C ./pie_hook_interface
	mkdir -p ./bin
	cp ./kernel_module/piehook.ko ./bin/piehook.ko
	cp ./pie_hook_interface/pie_interface ./bin/pie_interface

clean:
	$(MAKE) clean -C ./kernel_module
	$(MAKE) clean -C ./cJSON
	$(MAKE) clean -C ./pie_hook_interface
	rm -rf ./bin