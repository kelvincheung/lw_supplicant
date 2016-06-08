-include .config

CROSS_COMPILE?=$(CONFIG_CROSS_COMPILE:"%"=%)
CC = $(CROSS_COMPILE)gcc
STRIP = $(CROSS_COMPILE)strip

OBJS = common.o \
	md5.o \
	rc4.o \
	sha1.o \
	aes.o \
	aes_wrap.o \
	eloop.o \
	wpa.c \
	preauth.o \
	wpa_supplicant.o \
	events.o \
	l2_packet_none.o \
	tls_none.o \
	main_none.o \
	drivers.o \
	os_none.o \
	config.o \
	config_none.o

CFLAGS = -O2 -Wall

ifdef CONFIG_INTERNAL_MD5
CFLAGS += -DINTERNAL_MD5
endif
ifdef CONFIG_INTERNAL_SHA1
CFLAGS += -DINTERNAL_SHA1
endif

wpa_supplicant: .config $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(CFLAGS) $(OBJS)
	$(STRIP) -d --strip-unneeded $@

all: wpa_supplicant

clean:
	rm -f *~ *.o *.d wpa_supplicant
distclean:
	rm -f *~ *.o *.d wpa_supplicant .config
