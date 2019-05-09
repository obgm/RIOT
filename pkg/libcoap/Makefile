PKG_NAME=libcoap
PKG_URL=https://github.com/obgm/libcoap
PKG_VERSION=0e55b42fd35c85fc61731eddf5edc641022cf9ec
PKG_LICENSE=BSD-2-Clause

all: git-download
	@cp $(PKG_BUILDDIR)/coap_config.h.riot $(PKG_BUILDDIR)/coap_config.h
	"$(MAKE)" -C $(PKG_BUILDDIR)/src -f $(CURDIR)/Makefile.libcoap

include $(RIOTBASE)/pkg/pkg.mk
