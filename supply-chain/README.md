# supply-chain/

Who has looked at each dependency, and which of them nobody has.

The three files here are **managed by `cargo vet`, not by hand**. `cargo vet
fmt` rewrites them and strips comments, which is why this explanation is a
separate file rather than a header inside `config.toml` — a comment written
there disappears on the next run and cannot be told from one nobody wrote.

| file | who writes it | what it says |
| --- | --- | --- |
| `config.toml` | `cargo vet` | the trusted `[imports]`, and the `[[exemptions]]` — every crate in the tree with no audit behind it |
| `audits.toml` | `cargo vet certify` | what *we* have read and are willing to vouch for |
| `imports.lock` | `cargo vet` | the exact audit sets fetched, so a run is reproducible |

## Why the exemption list starts long

`cargo vet init` writes one exemption per existing dependency. The alternative —
failing a repository that already builds — would just teach everyone to delete
the file. So a list that started empty would have been a lie. The list as
written is the honest inventory: **this is the unreviewed surface, named.**

## What makes this a gate rather than a ledger

What happens *next*. A crate added tomorrow has no exemption and no audit, so
`cargo vet` fails and the pull request has to say something about it.

That is the control this repository did not otherwise have. `--locked` proves
the tree that builds is the tree that was reviewed. `cargo deny` asks where a
crate came from. `osv-scanner` asks whether it has been reported. **None of them
notices a new dependency name arriving** — and a new name is what a typosquat, a
slopsquatted hallucination, and a compromised transitive bump all look like on
the way in.

## The imports are not decoration

Six organisations publish audits of the crates.io commons: Mozilla, Google, the
Bytecode Alliance, ISRG, Zcash and Embark. Importing them retired 6 of the 17
exemptions this store opened with, without anyone here reading a line of
someone else's code. The 11 that remain are the crates none of those six has
looked at either.

## Shrinking the list

```sh
cargo vet diff <crate> <from> <to>   # exactly what changed between two versions
cargo vet certify <crate> <version>  # record that someone read it
cargo vet prune                      # drop exemptions an import now covers
```

Run `prune` after any import refresh. It is the only command here that makes
the store smaller on its own.
