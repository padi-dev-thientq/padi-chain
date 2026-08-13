# padi-chain — a Makefile for the commands you would otherwise type.
#
# Every target here wraps something that works on its own; nothing is hidden
# behind a script you cannot read. Run `make help` for the list.
#
# Variables can be overridden on the command line:
#     make run DATADIR=./othernode RPC_ADDR=127.0.0.1:9545

BINARY      ?= padi-chain
DATADIR     ?= ./data
CHAINID     ?= 1337
PERIOD      ?= 2
GASLIMIT    ?= 30000000
PASSWORD    ?= devpass
CLUSTER     ?= ./cluster

RPC_ADDR    ?= 127.0.0.1:8545
P2P_ADDR    ?= 0.0.0.0:30303
MONITOR     ?= 127.0.0.1:6060
RPC         ?= http://$(RPC_ADDR)
MONITOR_URL ?= http://$(MONITOR)

LOG         ?= $(DATADIR)/node.log
PIDFILE     ?= $(DATADIR)/node.pid

# The validator address is read back from the keystore rather than pasted in,
# so `make init && make start` works without copying an address by hand.
VALIDATOR = $(shell ./$(BINARY) account list -datadir $(DATADIR) 2>/dev/null | head -1)

GO       ?= go
GOFILES   = $(shell find . -name '*.go' -not -path './vendor/*')

.DEFAULT_GOAL := help

# ---------------------------------------------------------------- development

.PHONY: help
help: ## Show this help
	@echo "padi-chain — targets:"
	@echo
	@grep -hE '^[a-zA-Z0-9_-]+:.*?## ' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'
	@echo
	@echo "Common flow:  make init && make start && make deploy CONTRACT=Counter.sol"

.PHONY: build
build: $(BINARY) ## Build the node binary

$(BINARY): $(GOFILES)
	$(GO) build -o $(BINARY) ./cmd/padi-chain

.PHONY: install
install: ## Install the binary into GOPATH/bin
	$(GO) install ./cmd/padi-chain

.PHONY: test
test: ## Run the test suite
	$(GO) test ./...

.PHONY: test-short
test-short: ## Run the fast tests only, skipping the cluster ones
	$(GO) test -short ./...

.PHONY: test-race
test-race: ## Run the test suite under the race detector
	$(GO) test -race -timeout 900s ./...

.PHONY: test-v
test-v: ## Run one package's tests verbosely, e.g. make test-v PKG=./consensus
	$(GO) test -v -count=1 $(or $(PKG),./...)

.PHONY: bench
bench: ## Run the benchmarks, e.g. make bench PKG=./crypto/bls12381
	$(GO) test -run XXX -bench . -benchtime 20x $(or $(PKG),./...)

.PHONY: fmt
fmt: ## Format the code
	gofmt -w .

.PHONY: vet
vet: ## Run go vet
	$(GO) vet ./...

.PHONY: check
check: ## Everything CI would run: formatting, vet, tests
	@unformatted=$$(gofmt -l .); \
	if [ -n "$$unformatted" ]; then echo "not gofmt'd:"; echo "$$unformatted"; exit 1; fi
	$(GO) vet ./...
	$(GO) test ./...

.PHONY: lines
lines: ## Count the code
	@echo "code: $$(find . -name '*.go' -not -name '*_test.go' | xargs cat | wc -l) lines"
	@echo "test: $$(find . -name '*_test.go' | xargs cat | wc -l) lines"
	@echo "deps: $$(grep -c require go.mod || true)"

# ---------------------------------------------------------------------- chain

.PHONY: init
init: build ## Create a chain and a validator in DATADIR
	@if [ -f $(DATADIR)/genesis.json ]; then \
		echo "$(DATADIR)/genesis.json already exists — run 'make clean-chain' first"; exit 1; \
	fi
	./$(BINARY) init -datadir $(DATADIR) -chainid $(CHAINID) -period $(PERIOD) \
		-gaslimit $(GASLIMIT) -password $(PASSWORD)

.PHONY: run
run: build ## Run a mining node in the foreground
	@test -n "$(VALIDATOR)" || { echo "no validator in $(DATADIR) — run 'make init'"; exit 1; }
	./$(BINARY) run -datadir $(DATADIR) -mine -validator $(VALIDATOR) -password $(PASSWORD) \
		-rpc $(RPC_ADDR) -addr $(P2P_ADDR) -monitor $(MONITOR)

.PHONY: start
start: build ## Start a mining node in the background
	@test -n "$(VALIDATOR)" || { echo "no validator in $(DATADIR) — run 'make init'"; exit 1; }
	@if [ -f $(PIDFILE) ] && kill -0 $$(cat $(PIDFILE)) 2>/dev/null; then \
		echo "already running as pid $$(cat $(PIDFILE))"; exit 1; \
	fi
	@./$(BINARY) run -datadir $(DATADIR) -mine -validator $(VALIDATOR) -password $(PASSWORD) \
		-rpc $(RPC_ADDR) -addr $(P2P_ADDR) -monitor $(MONITOR) > $(LOG) 2>&1 & echo $$! > $(PIDFILE)
	@sleep 2
	@echo "started as pid $$(cat $(PIDFILE)), logging to $(LOG)"

.PHONY: follow
follow: build ## Run a non-mining node that follows PEERS
	./$(BINARY) run -datadir $(DATADIR) -rpc $(RPC_ADDR) -addr $(P2P_ADDR) \
		-monitor $(MONITOR) -peers $(PEERS)

.PHONY: stop
stop: ## Stop the background node
	@if [ -f $(PIDFILE) ]; then \
		kill $$(cat $(PIDFILE)) 2>/dev/null && echo "stopped $$(cat $(PIDFILE))" || echo "not running"; \
		rm -f $(PIDFILE); \
	else echo "no pidfile at $(PIDFILE)"; fi

.PHONY: logs
logs: ## Follow the node log
	@tail -f $(LOG)

.PHONY: status
status: build ## Print the chain status
	@./$(BINARY) status -rpc $(RPC)

.PHONY: health
health: ## Print the readiness check
	@curl -s $(MONITOR_URL)/health/ready; echo

.PHONY: metrics
metrics: ## Print the node's metrics
	@curl -s $(MONITOR_URL)/metrics | grep -v '^#'

.PHONY: prune
prune: ## Ask the running node to prune its state now
	@./$(BINARY) prune -monitor $(MONITOR_URL)

.PHONY: validators
validators: ## List the active validator set
	@curl -s -X POST -H 'Content-Type: application/json' \
		--data '{"jsonrpc":"2.0","id":1,"method":"padi_validators"}' $(RPC)

# ------------------------------------------------------------------- accounts

.PHONY: account
account: build ## Create a new account
	@./$(BINARY) account new -datadir $(DATADIR) -password $(PASSWORD)

.PHONY: accounts
accounts: build ## List accounts
	@./$(BINARY) account list -datadir $(DATADIR)

.PHONY: balance
balance: build ## Print a balance, e.g. make balance ADDR=0x...
	@test -n "$(ADDR)" || { echo "usage: make balance ADDR=0x..."; exit 1; }
	@./$(BINARY) balance -rpc $(RPC) $(ADDR)

# ------------------------------------------------------------------ contracts

.PHONY: compile
compile: ## Compile a Solidity file, e.g. make compile CONTRACT=Counter.sol
	@test -n "$(CONTRACT)" || { echo "usage: make compile CONTRACT=Counter.sol"; exit 1; }
	@command -v solc >/dev/null || { echo "solc is not installed"; exit 1; }
	solc --optimize --combined-json bin,abi $(CONTRACT) > $(basename $(CONTRACT)).json
	@echo "wrote $(basename $(CONTRACT)).json"

.PHONY: deploy
deploy: build compile ## Deploy a contract, e.g. make deploy CONTRACT=Counter.sol ARGS=0x...
	@test -n "$(VALIDATOR)" || { echo "no account in $(DATADIR)"; exit 1; }
	@bin=$$(python3 -c "import json,sys; d=json.load(open('$(basename $(CONTRACT)).json')); print(list(d['contracts'].values())[0]['bin'])"); \
	tx=$$(./$(BINARY) send -rpc $(RPC) -datadir $(DATADIR) -from $(VALIDATOR) \
		-password $(PASSWORD) -data 0x$${bin}$(subst 0x,,$(ARGS)) -gas $(or $(GAS),1000000)); \
	echo "tx: $$tx"; \
	echo "waiting for inclusion..."; \
	for i in $$(seq 1 30); do \
		sleep 1; \
		addr=$$(curl -s -X POST -H 'Content-Type: application/json' \
			--data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_getTransactionReceipt\",\"params\":[\"$$tx\"]}" $(RPC) \
			| python3 -c "import json,sys; r=json.load(sys.stdin).get('result'); print(r['contractAddress'] if r else '')" 2>/dev/null); \
		if [ -n "$$addr" ]; then echo "contract: $$addr"; exit 0; fi; \
	done; \
	echo "not mined within 30s"; exit 1

.PHONY: call
call: build ## Read-only call, e.g. make call TO=0x... DATA=0x06661abd
	@test -n "$(TO)" || { echo "usage: make call TO=0x... DATA=0x..."; exit 1; }
	@./$(BINARY) call -rpc $(RPC) -to $(TO) -data $(DATA)

.PHONY: send
send: build ## Send a transaction, e.g. make send TO=0x... DATA=0x... VALUE=0
	@test -n "$(TO)" || { echo "usage: make send TO=0x... [DATA=0x...] [VALUE=wei]"; exit 1; }
	@./$(BINARY) send -rpc $(RPC) -datadir $(DATADIR) -from $(or $(FROM),$(VALIDATOR)) \
		-password $(PASSWORD) -to $(TO) -data $(or $(DATA),0x) \
		-value $(or $(VALUE),0) $(if $(GAS),-gas $(GAS),)

.PHONY: selector
selector: ## Print a function selector, e.g. make selector SIG='increment(uint256)'
	@test -n "$(SIG)" || { echo "usage: make selector SIG='increment(uint256)'"; exit 1; }
	@hex=$$(printf '%s' "$(SIG)" | od -An -tx1 | tr -d ' \n'); \
	curl -s -X POST -H 'Content-Type: application/json' \
		--data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"web3_sha3\",\"params\":[\"0x$$hex\"]}" $(RPC) \
		| python3 -c "import json,sys; print(json.load(sys.stdin)['result'][:10])"

.PHONY: word
word: ## ABI-encode a number as a 32-byte word, e.g. make word N=41
	@printf '%064x\n' $(N)

# ---------------------------------------------------------------------- demos

.PHONY: devnet
devnet: ## Wipe, create and start a fresh single-node chain
	@$(MAKE) --no-print-directory stop 2>/dev/null || true
	@$(MAKE) --no-print-directory clean-chain
	@$(MAKE) --no-print-directory init
	@$(MAKE) --no-print-directory start
	@$(MAKE) --no-print-directory status

.PHONY: cluster
cluster: build ## Start a four-validator cluster locally (ports 8541-8544)
	@$(MAKE) --no-print-directory cluster-stop 2>/dev/null || true
	@rm -rf $(CLUSTER) && mkdir -p $(CLUSTER)
	@for i in 1 2 3 4; do \
		./$(BINARY) account new -datadir $(CLUSTER)/n$$i -password $(PASSWORD) >/dev/null; \
	done
	@vals=$$(for i in 1 2 3 4; do ./$(BINARY) account list -datadir $(CLUSTER)/n$$i | head -1; done | paste -sd,); \
	./$(BINARY) init -datadir $(CLUSTER)/n1 -chainid $(CHAINID) -period 2 -validators $$vals >/dev/null
	@for i in 2 3 4; do cp $(CLUSTER)/n1/genesis.json $(CLUSTER)/n$$i/genesis.json; done
	@for i in 1 2 3 4; do \
		v=$$(./$(BINARY) account list -datadir $(CLUSTER)/n$$i | head -1); \
		p=""; [ $$i -gt 1 ] && p="-peers 127.0.0.1:30301"; \
		./$(BINARY) run -datadir $(CLUSTER)/n$$i -mine -validator $$v -password $(PASSWORD) \
			-rpc 127.0.0.1:854$$i -addr 127.0.0.1:3030$$i -monitor 127.0.0.1:606$$i \
			-nat extip:127.0.0.1 $$p \
			> $(CLUSTER)/n$$i.log 2>&1 & \
	done
	@printf 'waiting for the first finalized block'
	@until ./$(BINARY) status -rpc http://127.0.0.1:8541 2>/dev/null \
		| grep -qE 'final: #[1-9]'; do printf '.'; sleep 2; done
	@echo
	@$(MAKE) --no-print-directory cluster-status

.PHONY: cluster-status
cluster-status: ## Show head and finalized height for each cluster node
	@for i in 1 2 3 4; do \
		printf 'node%s  ' $$i; \
		./$(BINARY) status -rpc http://127.0.0.1:854$$i 2>/dev/null \
			| grep -E 'head:|final:|peers:' | tr -s ' ' | tr '\n' ' '; \
		echo; \
	done

.PHONY: cluster-stop
cluster-stop: ## Stop the local cluster and delete its data
	@pkill -x $(BINARY) 2>/dev/null || true
	@rm -rf $(CLUSTER)

.PHONY: clean-chain
clean-chain: ## Delete the chain data, keeping the binary
	rm -rf $(DATADIR)

.PHONY: clean
clean: ## Delete the binary and all build output
	rm -f $(BINARY)
	$(GO) clean -cache -testcache 2>/dev/null || true
