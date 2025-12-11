#include <chainparams.h>
#include <primitives/block.h>
#include <uint256.h>
#include <arith_uint256.h>
#include <iostream>

// Function to create the genesis block
static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript,
                                 uint32_t nTime, uint32_t nNonce, uint32_t nBits,
                                 int32_t nVersion, const CAmount& genesisReward)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4)
        << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

// Mine genesis for one network
void MineGenesis(const char* networkName, uint32_t nTime, uint32_t nBits, const CAmount& reward) {
    const char* pszTimestamp = "The MultiVerse begins 2025-12-11";
    CScript genesisOutputScript = CScript() << ParseHex(
        "040184710fa689ad5023690c80f3a49c8f13f8d45b8c857fbcbc8bc4a8e4d3eb4b10f4d4604fa08dce601aaf0f470216fe1b51850b4acf21b179c45070ac7b03a9"
    ) << OP_CHECKSIG;

    uint32_t nNonce = 0;
    arith_uint256 powLimit;
    powLimit.SetCompact(nBits);

    std::cout << "Mining " << networkName << " genesis block..." << std::endl;

    while (true) {
        CBlock genesis = CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, 1, reward);
        uint256 hash = genesis.GetHash();
        arith_uint256 hashArith = UintToArith256(hash);

        if (hashArith <= powLimit) {
            std::cout << "✅ Found " << networkName << " genesis block!" << std::endl;
            std::cout << "Nonce: " << nNonce << std::endl;
            std::cout << "Hash: " << hash.ToString() << std::endl;
            std::cout << "Merkle: " << genesis.hashMerkleRoot.ToString() << std::endl << std::endl;
            break;
        }

        nNonce++;
        if (nNonce % 1000000 == 0) {
            std::cout << networkName << " tried nonce " << nNonce << std::endl;
        }
    }
}

int main() {
    // Mainnet
    MineGenesis("Mainnet", 1734220800, 0x1e0ffff0, 50 * COIN);

    // Testnet
    MineGenesis("Testnet", 1734220800, 0x1e0ffff0, 50 * COIN);

    // Regtest
    MineGenesis("Regtest", 1734220800, 0x207fffff, 50 * COIN);

    return 0;
}
