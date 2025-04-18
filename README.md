# IDL Guesser

IDL Guesser is an open-source tool that automatically recovers the IDL information from closed-source Anchor-based Solana programs. 

Check out our [blog post](https://www.sec3.dev/blog/idl-guesser-recovering-instruction-layouts-from-closed-source-solana-programs) for an in-depth discussion of how the tool works and the ideas behind it.

## Installation

Clone the repository and build the tool:

```bash
git clone https://github.com/sec3-service/IDLGuesser.git
cd IDLGuesser
cargo build --release
```

## Usage

Run the tool from the command line:

```bash
Usage: idl-guesser [OPTIONS] <PROGRAM_ID>

Arguments:
  <PROGRAM_ID>  The program ID to analyze

Options:
  -u, --url <URL>    Solana JSON RPC endpoint [default: https://api.mainnet-beta.solana.com]
  -v, --verbose      Verbose logging
  -f, --force-guess  Force guess the IDL even if a public IDL exists
      --export-asm   Export the disassembled assembly code to asm.txt
  -h, --help         Print help
```

## Example

Below is an example workflow using IDL Guesser:

```
❯ ./idl-guesser pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA
Generated IDL for pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA
Saved IDL to pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA.json

❯ cat pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA.json
{
  "address": "pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA",
  "metadata": {
    "name": "IDL",
    "version": "1.0.0",
    "spec": "0.1.0",
    "description": "Generated by IDL Guesser"
  },
  "instructions": [
    {
      "name": "buy",
      "discriminator": [
        102,
        6,
        61,
        18,
        1,
        218,
        235,
        234
      ],
      "accounts": [
        {
          "name": "pool"
        },
        {
          "name": "user",
          "writable": true,
          "signer": true
        },
        {
          "name": "global_config"
        },
        {
          "name": "base_mint"
        },
        {
          "name": "quote_mint"
        },
        {
          "name": "user_base_token_account",
          "writable": true
        },
        {
          "name": "user_quote_token_account",
          "writable": true
        },
        {
          "name": "pool_base_token_account",
          "writable": true
        },
        {
          "name": "pool_quote_token_account",
          "writable": true
        },
        {
          "name": "protocol_fee_recipient"
        },
        {
          "name": "protocol_fee_recipient_token_account",
          "writable": true
        },
        {
          "name": "base_token_program"
        },
        {
          "name": "quote_token_program"
        },
        {
          "name": "system_program"
        },
        {
          "name": "associated_token_program"
        },
        {
          "name": "event_authority"
        },
        {
          "name": "program"
        }
      ],
      "args": [
        {
          "name": "field_0",
          "type": "u64"
        },
        {
          "name": "field_1",
          "type": "u64"
        }
      ]
    },
...
```