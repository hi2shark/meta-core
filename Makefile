NAME=clash-meta-nw
BINDIR=bin
BRANCH=$(shell git branch --show-current)
ifeq ($(BRANCH),nw)
VERSION=nw-$(shell git rev-parse --short HEAD)
else ifeq ($(BRANCH),)
VERSION=$(shell git describe --tags --always)
else
VERSION=$(shell git rev-parse --short HEAD)
endif

BUILDTIME=$(shell date -u)
GOBUILD=CGO_ENABLED=0 go build -tags with_gvisor -trimpath -ldflags '-X "github.com/metacubex/mihomo/constant.Version=$(VERSION)" \
		-X "github.com/metacubex/mihomo/constant.BuildTime=$(BUILDTIME)" \
		-w -s -buildid='

PLATFORM_LIST = \
	darwin-amd64-v1 \
	darwin-amd64-v2 \
	darwin-amd64-v3 \
	darwin-arm64 \
	linux-amd64-v1 \
	linux-amd64-v2 \
	linux-amd64-v3 \
	linux-arm64

WINDOWS_ARCH_LIST = \
	windows-amd64-v1 \
	windows-amd64-v2 \
	windows-amd64-v3 \
	windows-arm64

OPENCLASH_LIST = \
	linux-amd64-v1 \
	linux-amd64-v2 \
	linux-amd64-v3 \
	linux-arm64

all: $(PLATFORM_LIST) $(WINDOWS_ARCH_LIST)

darwin-amd64-v1:
	GOARCH=amd64 GOOS=darwin GOAMD64=v1 $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

darwin-amd64-v2:
	GOARCH=amd64 GOOS=darwin GOAMD64=v2 $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

darwin-amd64-v3:
	GOARCH=amd64 GOOS=darwin GOAMD64=v3 $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

darwin-arm64:
	GOARCH=arm64 GOOS=darwin $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

linux-amd64-v1:
	GOARCH=amd64 GOOS=linux GOAMD64=v1 $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

linux-amd64-v2:
	GOARCH=amd64 GOOS=linux GOAMD64=v2 $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

linux-amd64-v3:
	GOARCH=amd64 GOOS=linux GOAMD64=v3 $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

linux-arm64:
	GOARCH=arm64 GOOS=linux $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

windows-amd64-v1:
	GOARCH=amd64 GOOS=windows GOAMD64=v1 $(GOBUILD) -o $(BINDIR)/$(NAME)-$@.exe

windows-amd64-v2:
	GOARCH=amd64 GOOS=windows GOAMD64=v2 $(GOBUILD) -o $(BINDIR)/$(NAME)-$@.exe

windows-amd64-v3:
	GOARCH=amd64 GOOS=windows GOAMD64=v3 $(GOBUILD) -o $(BINDIR)/$(NAME)-$@.exe

windows-arm64:
	GOARCH=arm64 GOOS=windows $(GOBUILD) -o $(BINDIR)/$(NAME)-$@.exe

linux_gz=$(addsuffix .gz, $(OPENCLASH_LIST))
darwin_gz=$(addsuffix .gz, $(filter darwin-%, $(PLATFORM_LIST)))
zip_releases=$(addsuffix .zip, $(WINDOWS_ARCH_LIST))

$(darwin_gz): %.gz : %
	chmod +x $(BINDIR)/$(NAME)-$(basename $@)
	gzip -f -S -$(VERSION).gz $(BINDIR)/$(NAME)-$(basename $@)

$(linux_gz): %.gz : %
	cp $(BINDIR)/$(NAME)-$(basename $@) $(BINDIR)/clash
	chmod +x $(BINDIR)/clash $(BINDIR)/$(NAME)-$(basename $@)
	tar -czf $(BINDIR)/clash-$(basename $@).tar.gz -C $(BINDIR) clash
	rm -f $(BINDIR)/clash
	gzip -f -S -$(VERSION).gz $(BINDIR)/$(NAME)-$(basename $@)

$(zip_releases): %.zip : %
	zip -m -j $(BINDIR)/$(NAME)-$(basename $@)-$(VERSION).zip $(BINDIR)/$(NAME)-$(basename $@).exe

openclash: $(linux_gz)
	cd $(BINDIR) && zip -j openclash-$(VERSION).zip \
		clash-linux-amd64-v1.tar.gz \
		clash-linux-amd64-v2.tar.gz \
		clash-linux-amd64-v3.tar.gz \
		clash-linux-arm64.tar.gz

releases: $(darwin_gz) $(linux_gz) $(zip_releases) openclash

vet:
	go test ./...

lint:
	golangci-lint run ./...

clean:
	rm -rf $(BINDIR)/*
