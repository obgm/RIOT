PKG_NAME=dcaf
PKG_URL=git@gitlab.informatik.uni-bremen.de:DCAF/dcaf.git
PKG_VERSION=54d3ed5593e6b95ec94fd0f528ea349b395e2f69
PKG_LICENSE=MIT

.PHONY: all

all: git-download
	"$(MAKE)" -C $(PKG_BUILDDIR)/src -f $(CURDIR)/Makefile.dcaf

include $(RIOTBASE)/pkg/pkg.mk
