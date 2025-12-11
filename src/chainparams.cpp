// MultiVerse (MVRS) chain parameters
// Forked from Litecoin for educational purposes
// Distributed under MIT license

#include <chainparams.h>
#include <chainparamsseeds.h>
#include <consensus/merkle.h>
#include <hash.h>
#include <tinyformat.h>
#include <util/system.h>
#include <util/strencodings.h>
#include <versionbitsinfo.h>
#include <assert.h>
#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/split.hpp>

// Genesis block creation function
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

static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits,
                                 int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "The MultiVerse begins 2025-12-11";
    const CScript genesisOutputScript = CScript() << ParseHex(
        "040184710fa689ad5023690c80f3a49c8f13f8d45b8c857fbcbc8bc4a8e4d3eb4b10f4d4604fa08dce601aaf0f470216fe1b51850b4acf21b179c45070ac7b03a9"
    ) << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}

/**
 * Main network
 */
class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = CBaseChainParams::MAIN;

        // Blockchain rules
        consensus.nSubsidyHalvingInterval = 500000; // halving every 500k blocks
        consensus.nPowTargetSpacing = 60;          // 1 minute per block
        consensus.powLimit = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");

        // Message start bytes and port
        pchMessageStart[0] = 0xf1;
        pchMessageStart[1] = 0xc2;
        pchMessageStart[2] = 0xb3;
        pchMessageStart[3] = 0xa4;
        nDefaultPort = 19777;

        // Genesis block placeholder
        genesis = CreateGenesisBlock(1734220800, 0, 0x1e0ffff0, 1, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        // After mining, replace the following:
        // consensus.hashGenesisBlock = uint256S("<MINED_HASH>");
        // assert(consensus.hashGenesisBlock == uint256S("<MINED_HASH>"));
        // assert(genesis.hashMerkleRoot == uint256S("<MINED_MERKLE>"));

        // Addresses
        bech32_hrp = "mvrs";
        base58Prefixes[PUBKEY_ADDRESS] = {48};
        base58Prefixes[SCRIPT_ADDRESS] = {5};
        base58Prefixes[SECRET_KEY] = {176};
    }
};

/**
 * Testnet
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = CBaseChainParams::TESTNET;
        consensus.nPowTargetSpacing = 60;
        pchMessageStart[0] = 0xf2;
        pchMessageStart[1] = 0xc3;
        pchMessageStart[2] = 0xb4;
        pchMessageStart[3] = 0xa5;
        nDefaultPort = 19778;

        genesis = CreateGenesisBlock(1734220800, 0, 0x1e0ffff0, 1, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();

        bech32_hrp = "tmvrs";
    }
};

/**
 * Regtest
 */
class CRegTestParams : public CChainParams {
public:
    explicit CRegTestParams(const ArgsManager&) {
        strNetworkID = CBaseChainParams::REGTEST;
        consensus.nPowTargetSpacing = 60;
        pchMessageStart[0] = 0xf3;
        pchMessageStart[1] = 0xc4;
        pchMessageStart[2] = 0xb5;
        pchMessageStart[3] = 0xa6;
        nDefaultPort = 19779;

        genesis = CreateGenesisBlock(1734220800, 0, 0x207fffff, 1, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();

        bech32_hrp = "rmvrs";
    }
};
