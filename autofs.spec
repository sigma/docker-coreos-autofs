#
#
%ifarch sparc i386 i586 i686
%define _lib lib
%endif

%ifarch x86_64 sparc64
%define _lib lib64
%endif

# Use --without systemd in your rpmbuild command or force values to 0 to
# disable them.
%define with_systemd        %{?_without_systemd:        0} %{?!_without_systemd:        1}

# Use --without libtirpc in your rpmbuild command or force values to 0 to
# disable them.
%define with_libtirpc        %{?_without_libtirpc:        0} %{?!_without_libtirpc:        1}

Summary: A tool from automatically mounting and umounting filesystems.
Name: autofs
%define version 5.1.1
%define release 1
Version: %{version}
Release: %{release}
License: GPL
Group: System Environment/Daemons
Source: ftp://ftp.kernel.org/pub/linux/daemons/autofs/v4/autofs-%{version}.tar.gz
Buildroot: %{_tmppath}/%{name}-tmp
%if %{with_systemd}
BuildRequires: systemd-units
%endif
%if %{with_libtirpc}
BuildRequires: libtirpc-devel
%endif
BuildRequires: autoconf, hesiod-devel, openldap-devel, bison, flex, cyrus-sasl-devel
Requires: chkconfig
Requires: /bin/bash mktemp sed textutils sh-utils grep /bin/ps
%if %{with_systemd}
Requires(post): systemd-sysv
Requires(post): systemd-units
Requires(preun): systemd-units
Requires(postun): systemd-units
%endif
Obsoletes: autofs-ldap
Summary(de): autofs daemon 
Summary(fr): démon autofs
Summary(tr): autofs sunucu süreci
Summary(sv): autofs-daemon

%description
autofs is a daemon which automatically mounts filesystems when you use
them, and unmounts them later when you are not using them.  This can
include network filesystems, CD-ROMs, floppies, and so forth.

%description -l de
autofs ist ein Dämon, der Dateisysteme automatisch montiert, wenn sie 
benutzt werden, und sie später bei Nichtbenutzung wieder demontiert. 
Dies kann Netz-Dateisysteme, CD-ROMs, Disketten und ähnliches einschließen. 

%description -l fr
autofs est un démon qui monte automatiquement les systèmes de fichiers
lorsqu'on les utilise et les démonte lorsqu'on ne les utilise plus. Cela
inclus les systèmes de fichiers réseau, les CD-ROMs, les disquettes, etc.

%description -l tr
autofs, kullanýlan dosya sistemlerini gerek olunca kendiliðinden baðlar
ve kullanýmlarý sona erince yine kendiliðinden çözer. Bu iþlem, að dosya
sistemleri, CD-ROM'lar ve disketler üzerinde yapýlabilir.

%description -l sv
autofs är en daemon som mountar filsystem när de använda, och senare
unmountar dem när de har varit oanvända en bestämd tid.  Detta kan
inkludera nätfilsystem, CD-ROM, floppydiskar, och så vidare.

%prep
%setup -q -n %{name}-%{version}
echo %{version}-%{release} > .version
%if %{with_systemd}
  %define unitdir %{?_unitdir:/lib/systemd/system}
  %define systemd_configure_arg --with-systemd
%endif
%if %{with_libtirpc}
  %define libtirpc_configure_arg --with-libtirpc
%endif

%build
CFLAGS="$RPM_OPT_FLAGS -Wall" \
LDFLAGS="-Wl,-z,now" \
./configure --libdir=%{_libdir} \
	--disable-mount-locking \
	--enable-ignore-busy \
	%{?systemd_configure_arg:} \
	%{?libtirpc_configure_arg:}
CFLAGS="$RPM_OPT_FLAGS -Wall" LDFLAGS="-Wl,-z,now" make initdir=/etc/rc.d/init.d DONTSTRIP=1

%install
rm -rf $RPM_BUILD_ROOT
%if %{with_systemd}
install -d -m 755 $RPM_BUILD_ROOT%{unitdir}
%else
mkdir -p -m755 $RPM_BUILD_ROOT/etc/rc.d/init.d
%endif
mkdir -p -m755 $RPM_BUILD_ROOT%{_sbindir}
mkdir -p -m755 $RPM_BUILD_ROOT%{_libdir}/autofs
mkdir -p -m755 $RPM_BUILD_ROOT%{_mandir}/{man5,man8}
mkdir -p -m755 $RPM_BUILD_ROOT/etc/sysconfig
mkdir -p -m755 $RPM_BUILD_ROOT/etc/auto.master.d

make install mandir=%{_mandir} initdir=/etc/rc.d/init.d INSTALLROOT=$RPM_BUILD_ROOT
echo make -C redhat
make -C redhat
%if %{with_systemd}
# Configure can get this wrong when the unit files appear under /lib and /usr/lib
find $RPM_BUILD_ROOT -type f -name autofs.service -exec rm -f {} \;
install -m 644 redhat/autofs.service $RPM_BUILD_ROOT%{unitdir}/autofs.service
%define init_file_name %{unitdir}/autofs.service
%else
install -m 755 redhat/autofs.init $RPM_BUILD_ROOT/etc/rc.d/init.d/autofs
%define init_file_name /etc/rc.d/init.d/autofs
%endif
install -m 644 redhat/autofs.conf $RPM_BUILD_ROOT/etc/autofs.conf
install -m 644 redhat/autofs.sysconfig $RPM_BUILD_ROOT/etc/sysconfig/autofs

%clean
[ "$RPM_BUILD_ROOT" != "/" ] && rm -rf $RPM_BUILD_ROOT

%post
%if %{with_systemd}
if [ $1 -eq 1 ]; then
	%{_bindir}/systemctl daemon-reload >/dev/null 2>&1 || :
	# autofs has been approved to be enabled by default
	%{_bindir}/systemctl enable %{name}.service >/dev/null 2>&1 || :
fi
%else
if [ $1 -eq 1 ]; then
	%{_sbindir}/chkconfig --add autofs
fi
%endif

%preun
%if %{with_systemd}
if [ $1 -eq 0 ] ; then
	%{_bindir}/systemctl --no-reload disable %{name}.service > /dev/null 2>&1 || :
	%{_bindir}/systemctl stop %{name}.service > /dev/null 2>&1 || :
fi
%else
if [ $1 -eq 0 ] ; then
	%{_sbindir}/service autofs stop > /dev/null 2>&1 || :
	%{_sbindir}/chkconfig --del autofs
fi
%endif

%postun
%if %{with_systemd}
%{_bindir}/systemctl daemon-reload >/dev/null 2>&1 || :
if [ $1 -ge 1 ] ; then
	# Package upgrade, not removal
	%{_bindir}/systemctl try-restart %{name}.service >/dev/null 2>&1 || :
fi
%else
if [ $1 -ge 1 ] ; then
	%{_sbindir}/service autofs condrestart > /dev/null 2>&1 || :
fi
%endif

#%triggerun -- %{name} < $bla release
## Save the current service runlevel info
## User must manually run systemd-sysv-convert --apply %{name}
## to migrate them to systemd targets
#%{_bindir}/systemd-sysv-convert --save %{name} >/dev/null 2>&1 ||:
#
## Run these because the SysV package being removed won't do them
#%{_sbindir}/chkconfig --del %{name} >/dev/null 2>&1 || :
#%{_bindir}/systemctl try-restart %{name}.service >/dev/null 2>&1 || :

%files
%defattr(-,root,root)
%doc CREDITS CHANGELOG INSTALL COPY* README* samples/ldap* samples/autofs.schema samples/autofs_ldap_auth.conf
%config %{init_file_name}
%config(noreplace) /etc/auto.master
%config(noreplace) /etc/autofs.conf
%config(noreplace,missingok) /etc/auto.misc
%config(noreplace,missingok) /etc/auto.net
%config(noreplace,missingok) /etc/auto.smb
%config(noreplace) /etc/sysconfig/autofs
%config(noreplace) /etc/autofs_ldap_auth.conf
%{_sbindir}/automount
%dir %{_libdir}/autofs
%{_libdir}/autofs/*
%{_mandir}/*/*
%dir /etc/auto.master.d

%changelog
* Fri Mar 28 2014 Ian Kent <raven@themaw.net>
- Update package to version 5.0.9.

* Thu Oct 17 2013 Ian Kent <raven@themaw.net>
- Update package to version 5.0.8.

* Wed Jul 25 2012 Ian Kent <raven@themaw.net>
- Update package to version 5.0.7.

* Tue Jun 3 2011 Ian Kent <raven@themaw.net>
- Update package to version 5.0.6.

* Thu Sep 3 2009 Ian Kent <raven@themaw.net>
- Update package to version 5.0.5.

* Tue Nov 4 2008 Ian Kent <raven@themaw.net>
- Update package to version 5.0.4.

* Tue Jun 18 2007 Ian Kent <raven@themaw.net>
- Update package to version 5.0.3.

* Tue Jun 18 2007 Ian Kent <raven@themaw.net>
- Update package to version 5.0.2.

* Thu Jul 13 2006 Ian Kent <raven@themaw.net>
- Rename package to version 5.0.1 to prevent problems when upgrading
  from packages labeled with beta.

* Tue Jun 29 2006 Ian Kent <raven@themaw.net>
- Update package to version 5.0.0_beta6.

* Tue Jun 20 2006 Ian Kent <raven@themaw.net>
- Update package to version 5.0.0_beta5.

* Fri Jun 2 2006 Ian Kent <raven@themaw.net>
- Update package to version 5.0.0_beta4.

* Tue May 23 2006 Ian Kent <raven@themaw.net>
- Update package to version 5.0.0_beta3.

* Tue May 9 2006 Ian Kent <raven@themaw.net>
- Update package to version 5.0.0_beta2.

* Mon May 1 2006 Ian Kent <raven@themaw.net>
- Update package to version 5.0.0_beta1.

* Wed Apr 6 2005 Ian Kent <raven@themaw.net>
- Update package to version 4.1.4.

* Mon Jan 4 2005 Ian Kent <raven@themaw.net>
- Update package spec file to add auto.smb program map example.

* Mon Jan 3 2005 Ian Kent <raven@themaw.net>
- Update package spec file to use autofs.sysconfig.

* Sat Jan 1 2005 Ian Kent <raven@themaw.net>
- Update package to version 4.1.4_beta1.

* Sat Apr 3 2004 Ian Kent <raven@themaw.net>
- Update package to version 4.1.2.

* Tue Jan 19 2004 Ian Kent <raven@themaw.net>
- Update spec file to version 4.1.1.
- Remove BuildRequires on LDAP and Hesoid as make allows
  for them to be missing.

* Thu Dec 11 2003 Ian Kent <raven@themaw.net>
- Updated spec file to standardise paths etc.

