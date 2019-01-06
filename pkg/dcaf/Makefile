PKG_NAME=dcaf
PKG_URL=git@gitlab.informatik.uni-bremen.de:DCAF/dcaf.git
PKG_VERSION=ce5ce02507a4267e14565613c806ee593c8a3ca5
PKG_LICENSE=MIT

CFLAGS += -Wno-implicit-fallthrough

.PHONY: all

all: git-download
	"$(MAKE)" -C $(PKG_BUILDDIR)/src -f $(CURDIR)/Makefile.dcaf

include $(RIOTBASE)/pkg/pkg.mk
