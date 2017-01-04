PREFIX=/usr
MANDIR=$(PREFIX)/share/man
BINDIR=$(PREFIX)/share/gpgit

all:
	  @echo "Run 'make install' for installation."
	  @echo "Run 'make uninstall' for uninstallation."

install:
		install -Dm755 gpgit.sh $(DESTDIR)$(PREFIX)/bin/gpgit
		install -Dm644 Readme.md $(DESTDIR)$(PREFIX)/share/doc/gpgit/Readme.md

uninstall:
		rm -f $(DESTDIR)$(PREFIX)/bin/gpgit
		rm -f $(DESTDIR)$(PREFIX)/share/doc/gpgit/Readme.md
