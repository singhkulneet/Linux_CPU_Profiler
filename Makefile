## [M1: point 1]
#  Explain following in here
#  ...
MODULE	 = perftop

## [M2: point 1]
#  Explain following in here
#  ...
obj-m += $(MODULE).o

## [M3: point 1]
#  Explain following in here
#  ...
KERNELDIR ?= /lib/modules/$(shell uname -r)/build
#KERNELDIR ?= ~/script/linux

## [M4: point 1]
#  Explain following in here
#  ...
PWD := $(shell pwd)

## [M5: point 1]
#  Explain following in here
#  ...
all: $(MODULE)


## [M6: point 1]
#  Explain following in here
#  ...
%.o: %.c
	@echo "  CC      $<"
	@$(CC) -c $< -o $@

## [M7: point 1]
#  Explain following in here
#  ...
$(MODULE):
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

## [M8: point 1]
#  Explain following in here
#  ...
clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean
