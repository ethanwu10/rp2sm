DOCKER ?= docker
DOCKER-BUILD ?= $(DOCKER) buildx build
GIT ?= git
TAR ?= tar # must be GNU tar
TARFLAGS := --numeric-owner --owner=0 --group=0 --sort=name --mtime=1970-01-01T00:00Z --no-xattr $(TARFLAGS)

dist_files = $(shell $(GIT) ls-files deploy) $(shell find out -type f) run.Dockerfile
source_files = $(dist_files) flag1.txt flag2.txt solve/loader.py solve/stg1.rp2b solve/stg2.rp2b
tar_transform = --transform 's|^|rp2sm/|;s|\brun\.Dockerfile\b|Dockerfile|'

.PHONY: default
default: help

.PHONY: all
all: pack/source.tar pack/dist.tar out
	@true

.PHONY: out
out:
	$(DOCKER-BUILD) . -f build.Dockerfile --target extractor -o type=local,dest=out

out/%: out
	@# dummy dependency resolution target
	@true

pack/source.tar: $(source_files)
	@mkdir -p pack
	$(TAR) $(TARFLAGS) $(tar_transform) -cf $@ $^

pack/dist.tar: $(dist_files)
	@mkdir -p pack
	$(TAR) $(TARFLAGS) $(tar_transform) -cf $@ $^

.PHONY: help
help:
	@echo "Available targets:"
	@echo ""
	@echo "    out:              compile binaries (in out/)"
	@echo "    pack/source.tar:  create \"source\" tarball (for challenge builds)"
	@echo "    pack/dist.tar:    create player-facing tarball"
	@echo "    all:              all of the above"
