
-include ../Makefile.conf
include ../Makefile.rules

all: autofs.init autofs.conf autofs.service

autofs.init: autofs.init.in
	sed -e "s|@@sbindir@@|$(sbindir)|g" \
	    -e "s|@@autofslibdir@@|$(autofslibdir)|g" \
	    -e "s|@@autofsconfdir@@|$(autofsconfdir)|g" \
	    -e "s|@@autofspiddir@@|$(autofspiddir)|g" \
	    -e "s|@@initdir@@|$(initdir)|g" < autofs.init.in > autofs.init

autofs.conf: autofs.conf.default.in
	sed -e "s|@@autofsmapdir@@|$(autofsmapdir)|g" \
		< autofs.conf.default.in > autofs.conf

autofs.service: ../samples/autofs.service.in
	sed -e "s|@@sbindir@@|$(sbindir)|g" \
	    -e "s|@@autofsconfdir@@|$(autofsconfdir)|g" \
	    -e "s|@@autofspiddir@@|$(autofspiddir)|g" \
		< ../samples/autofs.service.in > autofs.service

clean:
	rm -f autofs.init autofs.sysconfig autofs.service

