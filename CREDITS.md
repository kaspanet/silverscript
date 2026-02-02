# Credits and Third-Party Licenses

SilverScript is a programming language for Bitcoin Cash smart contracts. While the SilverScript compiler is an original implementation, this project incorporates and builds upon work from the CashScript project.

## Acknowledgements

- **CashScript**: SilverScript is heavily inspired by the [CashScript](https://cashscript.org/) language. We are grateful to Rosco Kalis and the CashScript contributors for their work in advancing Bitcoin Cash smart contract development.

## Third-Party Components

### 1. Language Grammar and Syntax
The SilverScript grammar specification (located in `src/silverscript.pest`) is a derivative work based on the [CashScript grammar documentation](https://cashscript.org/docs/compiler/grammar).

### 2. Contract Examples
Many smart contract examples included in this repository (e.g., in the `/tests` directory) are sourced or adapted from the CashScript repository.

---

## License for CashScript Components

The components listed above are used under the terms of the MIT License:

```
Copyright 2019 Rosco Kalis

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
```