# MultiVerse (MVRS)

**MultiVerse (MVRS)** is a new blockchain and cryptocurrency inspired by Litecoin.  
It enables instant peer-to-peer transactions and supports **mobile-friendly mining**.

---

## Features

- Own blockchain and genesis block  
- Mobile mining compatible (1-minute block interval)  
- Peer-to-peer transactions with no central authority  
- Open-source and MIT licensed  

---

## Getting Started

These instructions will get you a working MVRS node on your mobile (Termux) or Linux system.

### 1. Clone the repository

```bash
git clone https://github.com/YourUsername/MultiVerse-MVRS.git
cd MultiVerse-MVRS

2. Install dependencies (Termux)
pkg update
pkg upgrade
pkg install git clang make cmake python3 pkg-config boost openssl

3. Compile the MVRS node
clang++ -std=c++17 src/*.cpp -o mvrs_node -lboost_system -lssl -lcrypto -lpthread

4. Run the node and start mining
./mvrs_node


