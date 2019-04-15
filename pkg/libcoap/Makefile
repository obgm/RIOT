PKG_NAME=libcoap
PKG_URL=https://github.com/obgm/libcoap
PKG_VERSION=cc2e660fe30a426fcaef6152f0fce562bbdde5ae
PKG_LICENSE=BSD-2-Clause

all: git-download
	@cp $(PKG_BUILDDIR)/coap_config.h.riot $(PKG_BUILDDIR)/coap_config.h
	"$(MAKE)" -C $(PKG_BUILDDIR)/src -f $(CURDIR)/Makefile.libcoap

include $(RIOTBASE)/pkg/pkg.mk
