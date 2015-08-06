#
# Makefile for autofs
#

-include ../Makefile.conf
include ../Makefile.rules

SRCS = automount.c indirect.c direct.c spawn.c module.c mount.c \
	lookup.c state.c flag.c
OBJS = automount.o indirect.o direct.o spawn.o module.o mount.o \
	lookup.o state.o flag.o

version := $(shell cat ../.version)

CFLAGS += -rdynamic $(DAEMON_CFLAGS) -D_GNU_SOURCE -I../include
CFLAGS += -DAUTOFS_LIB_DIR=\"$(autofslibdir)\" 
CFLAGS += -DAUTOFS_MAP_DIR=\"$(autofsmapdir)\"
CFLAGS += -DAUTOFS_CONF_DIR=\"$(autofsconfdir)\"
CFLAGS += -DAUTOFS_FIFO_DIR=\"$(autofsfifodir)\"
CFLAGS += -DAUTOFS_FLAG_DIR=\"$(autofsflagdir)\"
CFLAGS += -DVERSION_STRING=\"$(version)\"
LDFLAGS += -rdynamic
LIBS += -ldl -lpthread

ifeq ($(LDAP), 1)
    CFLAGS += $(XML_FLAGS)
    LIBS += $(XML_LIBS)
endif

all: automount

automount: $(OBJS) $(AUTOFS_LIB)
	$(CC) $(LDFLAGS) $(DAEMON_LDFLAGS) -o automount $(OBJS) $(AUTOFS_LIB) $(LIBS)
	$(STRIP) automount

clean:
	rm -f *.o *.s *~ automount

install: all
	install -d -m 755 $(INSTALLROOT)$(sbindir)
	install -c automount -m 755 $(INSTALLROOT)$(sbindir)


