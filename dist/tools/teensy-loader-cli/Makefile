PKG_NAME=teensy-loader-cli
PKG_LICENSE=GPL-3
PKG_BUILDDIR=$(CURDIR)/bin

# get sources from repository
ifeq ($(OS),Darwin)
  # hacked version to make it work on MACOSX
  PKG_URL=https://github.com/alswl/teensy_loader_cli.git
  PKG_VERSION=9c16bb0add3ba847df5509328ad6bd5bc09d9ecd
else
  PKG_URL=https://github.com/PaulStoffregen/teensy_loader_cli.git
  PKG_VERSION=76921edbdd81ae99b869b104404c16c06b0a266f
endif

include $(RIOTBASE)/pkg/pkg.mk

all:
	env -i PATH=$(PATH) TERM=$(TERM) "$(MAKE)" -C $(PKG_BUILDDIR)
	mv $(PKG_BUILDDIR)/teensy_loader_cli ./teensy_loader
