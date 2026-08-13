# Running a chain

Every command below was run against this code. The output shown is real.

## 1. Build

```
$ go build -o layer1 ./cmd/layer1
```

No dependencies to fetch — the module requires nothing beyond the standard
library.

## 2. Create a chain

```
$ ./layer1 init -datadir ./data -chainid 1337 -period 2
Created validator account 0x9c723c00c6C1bB9d179b0a14860C37F8ab1611eb
Wrote data/genesis.json
Chain id 1337, block period 2s, 1 validator(s)
```

`init` writes a genesis file and, because no validators were named, creates one
and stakes it. It is pre-funded with a million units, which is what you will
deploy contracts with. `data/genesis.json` is the whole specification: share it
and anyone can join the same chain.

For a multi-validator chain, name them instead:

```
$ ./layer1 init -datadir ./data -validators 0xAAA...,0xBBB... -alloc 0xCCC...=1000000000000000000
```

## 3. Start the node

```
$ ./layer1 run -datadir ./data -mine \
      -validator 0x9c723c00c6C1bB9d179b0a14860C37F8ab1611eb \
      -rpc 127.0.0.1:8545 -monitor 127.0.0.1:6060 -addr 0.0.0.0:30303
```

`-mine` makes it propose blocks; without it the node follows. `-addr` is the
peer port, `-rpc` the JSON-RPC port, `-monitor` metrics and health.

```
$ ./layer1 status
chain id: 1337
head:     #4 0xe0b0b132...
final:    #4
quorum:   1 of 1 validators
```

`final` is the height that can no longer be reorganised. With one validator it
tracks the head; with more it lags until a quorum has attested.

## 4. Deploy a contract

Any Solidity contract compiled for Ethereum works unmodified.

```solidity
// Counter.sol
pragma solidity ^0.8.20;

contract Counter {
    uint256 public count;
    address public owner;
    event Incremented(address indexed by, uint256 newCount);
    error NotOwner(address caller);

    constructor(uint256 start) { count = start; owner = msg.sender; }

    function increment(uint256 by) external returns (uint256) {
        count += by;
        emit Incremented(msg.sender, count);
        return count;
    }

    function reset() external {
        if (msg.sender != owner) revert NotOwner(msg.sender);
        count = 0;
    }
}
```

```
$ solc --optimize --combined-json bin,abi Counter.sol > out.json
```

Deploy by sending the creation bytecode with no recipient. Constructor
arguments are appended ABI-encoded — here `100` as a 32-byte word:

```
$ ARG=$(printf '%064x' 100)
$ BIN=$(python3 -c "import json;d=json.load(open('out.json'));print(list(d['contracts'].values())[0]['bin'])")
$ ./layer1 send -from 0x9c72... -data 0x${BIN}${ARG} -gas 500000
0x6591777cecdc84803c294255b811b41f86b3710375ee07cb9c984d6c4f3fe7e8
```

The receipt carries the address:

```
$ curl -s -X POST -H 'Content-Type: application/json' \
    --data '{"jsonrpc":"2.0","id":1,"method":"eth_getTransactionReceipt",
             "params":["0x6591777c..."]}' http://127.0.0.1:8545
{"status":"0x1","contractAddress":"0x8b1d701fe4b9ddb09b6e831acf78368dabc22e34","gasUsed":"0x2ed8f", ...}
```

## 5. Use it

Reading costs nothing and runs against a copy of the state:

```
$ ./layer1 call -to 0x8b1d701f... -data 0x06661abd     # count()
0x0000000000000000000000000000000000000000000000000000000000000064   # 100
```

Writing is a signed transaction. The selector is the first four bytes of
`keccak256("increment(uint256)")`, followed by the argument:

```
$ ./layer1 send -from 0x9c72... -to 0x8b1d701f... \
      -data 0x7cf5dab0$(printf '%064x' 41) -gas 100000
$ ./layer1 call -to 0x8b1d701f... -data 0x06661abd
0x000000000000000000000000000000000000000000000000000000000000008d   # 141
```

Events and revert reasons come through the standard RPC. A custom error is
returned as its selector and arguments, exactly as Ethereum encodes it:

```
eth_getLogs  -> 1 log, topic0 0x38ac789e..., data 141
eth_call reset() from a stranger
             -> execution reverted: 0x245aecd3000000...1111  (NotOwner(address))
```

Selectors are `keccak256(signature)[:4]`; the node will compute them for you
with `web3_sha3` if you have no other tooling to hand.

## 6. Add a second node

```
$ ./layer1 init -datadir ./data2 ...        # or copy data/genesis.json across
$ cp data/genesis.json data2/genesis.json
$ ./layer1 run -datadir ./data2 -addr 0.0.0.0:30304 -rpc 127.0.0.1:8546 \
      -peers 127.0.0.1:30303
```

The second node authenticates, syncs, and follows. A node that is far behind
takes a finalized snapshot from its peer instead of replaying the chain.

## 7. Become a validator

Staking is a transaction to the system account at
`0x00000000000000000000000000000000000000ff`, carrying the stake as value and
the attestation key with its proof of possession as call data:

```
0x01 || withdrawalAddress(20) || blsPublicKey(48) || proofOfPossession(96)
```

The node derives its own attestation key from its validator key. After the
deposit, the validator joins at the next epoch boundary, subject to the churn
limit.

```
$ ./layer1 send -from <validator> -to 0x00000000000000000000000000000000000000ff \
      -value 32000000000000000000 -data 0x01<withdrawal><blsKey><proof> -gas 500000
```

`layer1_validatorInfo` reports where a validator sits in its lifecycle.

## Operating

```
$ curl -s localhost:6060/metrics        # Prometheus
$ curl -s localhost:6060/health/ready   # 503 when the head has gone stale
$ curl -s -XPOST localhost:6060/admin/prune
```

`-archive` keeps every historical state; the default prunes to the last 256
blocks plus whatever is finalized.

## A warning worth repeating

This chain has not been audited and has never run in public. The quickstart
above works, which is not the same as being safe to put value on.
