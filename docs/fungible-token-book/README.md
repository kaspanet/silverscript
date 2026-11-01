# Fungible Token Book

This directory contains an `mdBook` explaining the `FungibleToken` and `FungibleTokenMinter` SilverScript examples.

These contracts are just examples, not token standards. They may contain errors and are not guaranteed to be secure. For the actual standard, see [KCC-20](https://github.com/kaspanet/kccs/blob/main/kcc-0020.md).

## Build

From the repository root:

```bash
mdbook build docs/fungible-token-book
```

The book uses Mermaid diagrams, so local builds also need `mdbook-mermaid`:

```bash
cargo install mdbook-mermaid
```

The rendered HTML book will be written to:

```text
docs/fungible-token-book/book
```

## Open

After building, open:

```text
docs/fungible-token-book/book/index.html
```

## Serve Locally

To preview the book with a local web server:

```bash
mdbook serve docs/fungible-token-book
```

By default, `mdbook serve` prints the local address to open in a browser.
