# Blinding a WOTS signature thanks to ZKBoo (MPC-in-the-head circuit)

This project implements a protocol based on **ZKBoo**, a zero-knowledge proof scheme. ZKBoo is designed to prove properties about data without revealing the data itself.

This project was carried out as part of my final internship for the Master's degree in Cryptology and Computer Security at [the University of Bordeaux](https://mastercsi.labri.fr/). The internship took place in the spring/summer of 2025 at [UPC in Barcelona](https://www.upc.edu/ca), under the supervision of [Javier Herranz Sotoca](https://web.mat.upc.edu/javier.herranz/).

### Key Features

- **ZKBoo**: Implementation of the ZKBoo protocol for zero-knowledge proofs.
- **Modularity**: Structured code to allow future extensions.
- **Performance**: Optimized for efficient computations.

### Project Structure

- `src/`: Contains the main source code.
- `tests/`: Contains unit tests.
- `README.md`: Project documentation.

### Third-Party Dependencies

This project includes a `third_party/` directory, which contains an older version of OpenSSL (1.0.2). This specific version was necessary to ensure compatibility with the original implementation from Aarhus University. While this dependency is outdated, it was required to faithfully reproduce and build upon their work.

### References

- [ZKBoo: Faster Zero-Knowledge for Boolean Circuits (ePrint)](https://eprint.iacr.org/2016/163)
- [GitHub Repository for ZKBoo Implementation](https://github.com/Sobuno/ZKBoo) (original implementation, which only included a ZK proof of knowledge of a SHA256 preimage)