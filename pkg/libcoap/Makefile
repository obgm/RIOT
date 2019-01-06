PKG_NAME=libcoap
PKG_URL=https://github.com/obgm/libcoap
PKG_VERSION=2292a95e438c8216714d922fcfc1d65680a73b99
PKG_LICENSE=BSD-2-Clause

all: git-download
	"$(MAKE)" -C $(PKG_BUILDDIR)/src -f $(CURDIR)/Makefile.libcoap

include $(RIOTBASE)/pkg/pkg.mk
