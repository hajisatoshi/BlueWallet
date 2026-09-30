# Bluug Wallet - Bitcoin BLAKE2b & Lightning Wallet

<p align="center">
  <img src="https://i.imgur.com/hHYJnMj.png" width="80%" alt="Bluug Wallet">
</p>

**Bluug Wallet** is a thin, open-source Bitcoin wallet built with React Native and Electrum, specifically tailored for the **Bitcoin BLAKE2b Hardfork** chain with native **Somali (Af-Soomaali)** localization.

---

## ⚡ BLAKE2b Fork Features

* **Bitcoin BLAKE2b Chain Support**: Full compatibility with the post-fork consensus rules (activation height `961,640+`).
* **164-Byte v2 Block Headers**: Custom header validation and timestamp extraction for BLAKE2b v2 proof-of-work block headers.
* **Unified Sighash (`0x21`)**: Implements Bitcoin Knots PR #357 / v29.4.1 unified opt-in signature hash (`SIGHASH_ALL | SIGHASH_UNIFIED = 0x21`):
  * Native SegWit (`HDSegwitBech32Wallet` / BIP84)
  * Wrapped SegWit (`SegwitP2SHWallet` / BIP49)
  * Legacy (`LegacyWallet` / BIP44 P2PKH)
  * Multisig HD (`MultisigHDWallet` BIP45/48/87) & PSBT cosigning workflows
* **Somali (Af-Soomaali) Translation**: Full native Somali localization across all screens and flows (*Boorsooyinka*, *Dirista*, *Helitaanka*, *Dhaqdhaqaaqyada*, *Dejinta*).
* **Shulcrum Electrum Server**: Optimized for connection to [Shulcrum](https://github.com/hajisatoshi/Fulcrum) / Fulcrum Electrum servers on port `50001`.
* **Mempool Guide Integration**: Default block explorer and fee estimation connected to [`https://mempool.guide`](https://mempool.guide).

---

## 🚀 Key Features

* **Self-Custody**: Private keys never leave your device.
* **SegWit-first & Multi-type**: Native SegWit (Bech32), Wrapped SegWit (P2SH), Legacy, and Multisig vaults.
* **PSBT & Hardware Support**: Air-gapped workflows, SeedQR, ColdCard, Cobo, Keystone, and Sparrow export/import.
* **Security & Privacy**: Plausible deniability, biometric authentication, storage encryption, and Tor support.
* **Multiple Languages**: 55+ languages supported including full Somali.

---

## 🛠️ Build & Run

### Prerequisites

* Node.js (LTS version recommended, Node 20 / 22)
* npm
* Android Studio (for Android builds) or Xcode (for iOS builds)

```bash
# Clone the repository
git clone -b blake2b-fork https://github.com/hajisatoshi/BlueWallet.git
cd BlueWallet

# Install dependencies
npm install
```

### Run on Android

```bash
# Start the Metro bundler
npm start

# In another terminal window:
npx react-native run-android
```

### Run on iOS

```bash
npx pod-install
npm start

# In another terminal window:
npx react-native run-ios
```

---

## 🧪 Tests

Run the full unit test suite including BLAKE2b unified sighash and header validation:

```bash
npm run unit
```

Run specific BLAKE2b fork tests:

```bash
npx jest tests/unit/unifiedSighash.test.ts
```

---

## 📜 Upstream & License

Forked from [BlueWallet](https://github.com/BlueWallet/BlueWallet). 
Licensed under the [MIT License](LICENSE).
