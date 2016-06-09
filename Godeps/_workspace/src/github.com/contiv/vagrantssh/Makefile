all: stop start test
	make stop

deps:
	go get github.com/tools/godep
	go get github.com/golang/lint/golint

reflex-test: start
	reflex -r '\.go' make test

test: deps start golint
	godep go test -v -tags vagrant ./... -check.v
	vagrant ssh host0 -c \
		"export GOPATH=/vagrant/:/vagrant/Godeps/_workspace; \
		 if [ \"${http_proxy}\" != \"\" ]; then export http_proxy=${http_proxy}; fi; \
		 if [ \"${https_proxy}\" != \"\" ]; then export https_proxy=${https_proxy}; fi; \
		 cd /vagrant/; \
		 go test -v -tags baremetal ./... -check.v"

golint: deps
	test -z "$$(golint ./... | tee /dev/stderr)"

stop:
	vagrant destroy -f

start:
	vagrant up --provider virtualbox
