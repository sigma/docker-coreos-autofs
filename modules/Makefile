#
# Makefile for autofs
#

-include ../Makefile.conf
include ../Makefile.rules

SRCS :=	lookup_file.c lookup_program.c  lookup_userhome.c \
	lookup_multi.c lookup_hosts.c lookup_dir.c \
	parse_sun.c parse_amd.c \
	mount_generic.c  mount_nfs.c  mount_afs.c  mount_autofs.c \
	mount_changer.c  mount_bind.c

MODS :=	lookup_file.so lookup_program.so lookup_userhome.so \
	lookup_multi.so lookup_hosts.so lookup_dir.so \
	parse_sun.so parse_amd.so \
	mount_generic.so mount_nfs.so mount_afs.so mount_autofs.so \
	mount_changer.so mount_bind.so

YACCSRC = amd_tok.c amd_parse.tab.c amd_parse.tab.h \

ifeq ($(EXT2FS), 1)
  SRCS += mount_ext2.c
  MODS += mount_ext2.so
else
 ifeq ($(EXT3FS), 1)
   SRCS += mount_ext2.c
   MODS += mount_ext2.so
 endif
endif

ifeq ($(HESIOD), 1)
  SRCS += lookup_hesiod.c  parse_hesiod.c
  MODS += lookup_hesiod.so parse_hesiod.so
endif

ifeq ($(NISPLUS), 1)
  SRCS += lookup_nisplus.c
  MODS += lookup_nisplus.so
endif

ifeq ($(YPCLNT), 1)
  SRCS += lookup_yp.c
  MODS += lookup_yp.so
endif

ifeq ($(LDAP), 1)
  SRCS += lookup_ldap.c
  MODS += lookup_ldap.so
  LDAP_FLAGS += $(XML_FLAGS) -DLDAP_THREAD_SAFE
  LIBLDAP += $(XML_LIBS)
  ifeq ($(SASL), 1)
    SASL_OBJ = cyrus-sasl.o cyrus-sasl-extern.o
    LDAP_FLAGS += $(SASL_FLAGS) $(KRB5_FLAGS)
    LIBLDAP += $(LIBSASL) $(KRB5_LIBS)
  endif
endif

ifeq ($(SSSD), 1)
  CFLAGS += -DSSS_LIB_DIR=\"$(ssslibdir)\"
  SRCS += lookup_sss.c
  MODS += lookup_sss.so
endif

CFLAGS += -I../include -I../lib -fPIC -D_GNU_SOURCE
CFLAGS += -DAUTOFS_LIB_DIR=\"$(autofslibdir)\"
CFLAGS += -DAUTOFS_MAP_DIR=\"$(autofsmapdir)\"

all: $(MODS)

clean:
	rm -f *.o *.s *.so *~

# mount_smbfs.so is an obsolete module which must be removed
install: all
	install -d -m 755 $(INSTALLROOT)$(autofslibdir)
	install -c $(MODS) -m 755 $(INSTALLROOT)$(autofslibdir)
	-rm -f $(INSTALLROOT)$(autofslibdir)/mount_smbfs.so
	ln -fs lookup_file.so $(INSTALLROOT)$(autofslibdir)/lookup_files.so
	ln -fs lookup_yp.so $(INSTALLROOT)$(autofslibdir)/lookup_nis.so
ifeq ($(LDAP), 1)
	ln -fs lookup_ldap.so $(INSTALLROOT)$(autofslibdir)/lookup_ldaps.so
endif
	ln -fs mount_nfs.so $(INSTALLROOT)$(autofslibdir)/mount_nfs4.so
ifeq ($(EXT2FS), 1)
 ifeq ($(EXT3FS), 1)
	ln -fs mount_ext2.so $(INSTALLROOT)$(autofslibdir)/mount_ext3.so
 endif
 ifeq ($(EXT4FS), 1)
	ln -fs mount_ext2.so $(INSTALLROOT)$(autofslibdir)/mount_ext4.so
 endif
else ifeq ($(EXT3FS), 1)
	mv $(INSTALLROOT)$(autofslibdir)/mount_ext2.so $(INSTALLROOT)$(autofslibdir)/mount_ext3.so
 ifeq ($(EXT4FS), 1)
	ln -fs mount_ext3.so $(INSTALLROOT)$(autofslibdir)/mount_ext4.so
 endif
else ifeq ($(EXT4FS), 1)
	mv $(INSTALLROOT)$(autofslibdir)/mount_ext2.so $(INSTALLROOT)$(autofslibdir)/mount_ext4.so
endif

amd_tok.c: amd_tok.l
	$(LEX) -o$@ -Pamd_ $?

amd_tok.o: amd_tok.c amd_parse.tab.h

amd_parse.tab.c amd_parse.tab.h: amd_parse.y
	$(YACC) -v -d -p amd_ -b amd_parse $?

amd_parse.tab.o: amd_parse.tab.c amd_parse.tab.h

parse_amd.so: parse_amd.c amd_parse.tab.o amd_tok.o
	$(CC) $(LDFLAGS) $(SOLDFLAGS) $(CFLAGS) -o parse_amd.so \
		parse_amd.c amd_parse.tab.o amd_tok.o $(AUTOFS_LIB) $(LIBS)
	$(STRIP) parse_amd.so

#
# Ad hoc compilation rules for modules which need auxilliary libraries
#
lookup_hesiod.so: lookup_hesiod.c
	$(CC) $(LDFLAGS) $(SOLDFLAGS) $(CFLAGS) $(HESIOD_FLAGS) -o lookup_hesiod.so \
		lookup_hesiod.c $(AUTOFS_LIB) $(LIBHESIOD) $(LIBRESOLV) $(LIBS)
	$(STRIP) lookup_hesiod.so

cyrus-sasl.o: cyrus-sasl.c
	$(CC) $(CFLAGS) $(LDAP_FLAGS) -c $<

cyrus-sasl-extern.o: cyrus-sasl-extern.c
	$(CC) $(CFLAGS) $(LDAP_FLAGS) -c $<

lookup_ldap.so: lookup_ldap.c dclist.o base64.o $(SASL_OBJ)
	$(CC) $(LDFLAGS) $(SOLDFLAGS) $(CFLAGS) $(LDAP_FLAGS) -o lookup_ldap.so \
		lookup_ldap.c dclist.o base64.o $(SASL_OBJ) \
		$(AUTOFS_LIB) $(LIBLDAP) $(LIBRESOLV) $(LIBS)
	$(STRIP) lookup_ldap.so

mount_nfs.so: mount_nfs.c replicated.o
	$(CC) $(LDFLAGS) $(SOLDFLAGS) $(CFLAGS) -o mount_nfs.so \
		mount_nfs.c replicated.o $(AUTOFS_LIB) $(LIBS)
	$(STRIP) mount_nfs.so

