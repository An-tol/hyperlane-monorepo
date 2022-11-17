#![allow(missing_docs)]

use std::str::FromStr;

use eyre::Result;
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;
use serde::{Deserialize, Serialize};
use strum::{EnumIter, EnumString};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Address(pub bytes::Bytes);

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Balance(pub num::BigInt);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractLocator {
    pub chain_name: String,
    pub domain: u32,
    pub address: Address,
}
impl std::fmt::Display for ContractLocator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}[@{}]+contract:0x{:x}",
            self.chain_name, self.domain, self.address.0
        )
    }
}

#[async_trait::async_trait]
pub trait Chain {
    /// Query the balance on a chain
    async fn query_balance(&self, addr: Address) -> Result<Balance>;
}

impl From<Address> for ethers::types::H160 {
    fn from(addr: Address) -> Self {
        ethers::types::H160::from_slice(addr.0.as_ref())
    }
}

impl From<ethers::types::H160> for Address {
    fn from(addr: ethers::types::H160) -> Self {
        Address(bytes::Bytes::from(addr.as_bytes().to_owned()))
    }
}

impl From<&'_ Address> for ethers::types::H160 {
    fn from(addr: &Address) -> Self {
        ethers::types::H160::from_slice(addr.0.as_ref())
    }
}

/// All domains supported by Hyperlane.
#[derive(FromPrimitive, EnumString, strum::Display, EnumIter, PartialEq, Eq, Debug)]
#[strum(serialize_all = "lowercase")]
pub enum HyperlaneDomain {
    /// Ethereum mainnet domain ID, decimal ID 6648936
    Ethereum = 0x657468,
    /// Ethereum testnet Goerli domain ID
    Goerli = 5,
    /// Ethereum testnet Kovan domain ID
    Kovan = 3000,

    /// Polygon mainnet domain ID, decimal ID 1886350457
    Polygon = 0x706f6c79,
    /// Polygon testnet Mumbai domain ID
    Mumbai = 80001,

    /// Avalanche mainnet domain ID, decimal ID 1635148152
    Avalanche = 0x61766178,
    /// Avalanche testnet Fuji domain ID
    Fuji = 43113,

    /// Arbitrum mainnet domain ID, decimal ID 6386274
    Arbitrum = 0x617262,
    /// Arbitrum testnet ArbitrumRinkeby domain ID, decimal ID 1634872690
    ArbitrumRinkeby = 0x61722d72,
    ArbitrumGoerli = 421613,

    /// Optimism mainnet domain ID, decimal ID 28528
    Optimism = 0x6f70,
    /// Optimism testnet OptimismKovan domain ID, decimal ID 1869622635
    OptimismKovan = 0x6f702d6b,
    OptimismGoerli = 420,

    /// BSC mainnet domain ID, decimal ID 6452067
    #[strum(serialize = "bsc")]
    BinanceSmartChain = 0x627363,
    /// BSC testnet, decimal ID 1651715444
    #[strum(serialize = "bsctestnet")]
    BinanceSmartChainTestnet = 0x62732d74,

    /// Celo domain ID, decimal ID 1667591279
    Celo = 0x63656c6f,
    /// Celo testnet Alfajores domain ID
    Alfajores = 1000,

    /// Moonbeam testnet MoonbaseAlpha domain ID, decimal ID 1836002657
    MoonbaseAlpha = 0x6d6f2d61,
    /// Moonbeam domain ID, decimal ID 1836002669
    Moonbeam = 0x6d6f2d6d,

    Zksync2Testnet = 280,

    // -- Local test chains --
    /// Test1 local chain
    Test1 = 13371,
    /// Test2 local chain
    Test2 = 13372,
    /// Test3 local chain
    Test3 = 13373,
}

impl From<HyperlaneDomain> for u32 {
    fn from(domain: HyperlaneDomain) -> Self {
        domain as u32
    }
}

impl TryFrom<u32> for HyperlaneDomain {
    type Error = eyre::Error;

    fn try_from(domain_id: u32) -> Result<Self, Self::Error> {
        FromPrimitive::from_u32(domain_id)
            .ok_or_else(|| eyre::eyre!("Unknown domain ID {domain_id}"))
    }
}

/// Types of Hyperlane domains.
pub enum HyperlaneDomainType {
    /// A mainnet.
    Mainnet,
    /// A testnet.
    Testnet,
    /// A local chain for testing (i.e. Hardhat node).
    LocalTestChain,
}

impl HyperlaneDomain {
    pub fn domain_type(&self) -> HyperlaneDomainType {
        match self {
            HyperlaneDomain::Ethereum => HyperlaneDomainType::Mainnet,
            HyperlaneDomain::Goerli => HyperlaneDomainType::Testnet,
            HyperlaneDomain::Kovan => HyperlaneDomainType::Testnet,

            HyperlaneDomain::Polygon => HyperlaneDomainType::Mainnet,
            HyperlaneDomain::Mumbai => HyperlaneDomainType::Testnet,

            HyperlaneDomain::Avalanche => HyperlaneDomainType::Mainnet,
            HyperlaneDomain::Fuji => HyperlaneDomainType::Testnet,

            HyperlaneDomain::Arbitrum => HyperlaneDomainType::Mainnet,
            HyperlaneDomain::ArbitrumRinkeby => HyperlaneDomainType::Testnet,
            HyperlaneDomain::ArbitrumGoerli => HyperlaneDomainType::Testnet,

            HyperlaneDomain::Optimism => HyperlaneDomainType::Mainnet,
            HyperlaneDomain::OptimismKovan => HyperlaneDomainType::Testnet,
            HyperlaneDomain::OptimismGoerli => HyperlaneDomainType::Testnet,

            HyperlaneDomain::BinanceSmartChain => HyperlaneDomainType::Mainnet,
            HyperlaneDomain::BinanceSmartChainTestnet => HyperlaneDomainType::Testnet,

            HyperlaneDomain::Celo => HyperlaneDomainType::Mainnet,
            HyperlaneDomain::Alfajores => HyperlaneDomainType::Testnet,

            HyperlaneDomain::MoonbaseAlpha => HyperlaneDomainType::Testnet,
            HyperlaneDomain::Moonbeam => HyperlaneDomainType::Mainnet,

            HyperlaneDomain::Zksync2Testnet => HyperlaneDomainType::Testnet,

            HyperlaneDomain::Test1 => HyperlaneDomainType::LocalTestChain,
            HyperlaneDomain::Test2 => HyperlaneDomainType::LocalTestChain,
            HyperlaneDomain::Test3 => HyperlaneDomainType::LocalTestChain,
        }
    }
}

/// Gets the name of the chain from a domain id.
/// Returns None if the domain ID is not recognized.
pub fn name_from_domain_id(domain_id: u32) -> Option<String> {
    HyperlaneDomain::try_from(domain_id)
        .ok()
        .map(|domain| domain.to_string())
}

/// Gets the domain ID of the chain its name.
/// Returns None if the chain name is not recognized.
pub fn domain_id_from_name(name: &'static str) -> Option<u32> {
    HyperlaneDomain::from_str(name)
        .ok()
        .map(|domain| domain.into())
}

#[cfg(test)]
mod tests {
    use config::{Config, File, FileFormat};
    use hyperlane_base::Settings;
    use std::collections::BTreeSet;
    use std::fs::read_to_string;
    use std::path::Path;
    use std::str::FromStr;
    use walkdir::WalkDir;

    use crate::{domain_id_from_name, name_from_domain_id, HyperlaneDomain};

    /// Relative path to the `hyperlane-monorepo/rust/config/`
    /// directory, which is where the agent's config files
    /// currently live.
    const AGENT_CONFIG_PATH_ROOT: &str = "../config";

    /// We will not include any file paths of config/settings files
    /// in the test suite if *any* substring of the file path matches
    /// against one of the strings included in the blacklist below.
    /// This is to ensure that e.g. when a backwards-incompatible
    /// change is made in config file format, and agents can't parse
    /// them anymore, we don't fail the test. (E.g. agents cannot
    /// currently parse the older files in `config/dev/` or
    /// `config/testnet`.
    const BLACKLISTED_DIRS: &[&str] = &[
        // Ignore only-local names of fake chains used by
        // e.g. test suites.
        "test/test_config.json",
    ];

    fn is_blacklisted(path: &Path) -> bool {
        BLACKLISTED_DIRS
            .iter()
            .any(|x| path.to_str().unwrap().contains(x))
    }

    #[derive(Clone, Debug, Ord, PartialEq, PartialOrd, Eq, Hash)]
    struct ChainCoordinate {
        name: String,
        domain: u32,
    }

    fn config_paths(root: &Path) -> Vec<String> {
        WalkDir::new(root)
            .min_depth(2)
            .into_iter()
            .filter_map(|x| x.ok())
            .map(|x| x.into_path())
            .filter(|x| !is_blacklisted(x))
            .map(|x| x.into_os_string())
            .filter_map(|x| x.into_string().ok())
            .collect()
    }

    /// Provides a vector of parsed `hyperlane_base::Settings` objects
    /// built from all of the version-controlled agent configuration files.
    /// This is purely a utility to allow us to test a handful of critical
    /// properties related to those configs and shouldn't be used outside
    /// of a test env. This test simply tries to do some sanity checks
    /// against the integrity of that data.
    fn hyperlane_settings() -> Vec<Settings> {
        let root = Path::new(AGENT_CONFIG_PATH_ROOT);
        let paths = config_paths(root);
        let files: Vec<String> = paths
            .iter()
            .filter_map(|x| read_to_string(x).ok())
            .collect();
        paths
            .iter()
            .zip(files.iter())
            .map(|(p, f)| {
                Config::builder()
                    .add_source(File::from_str(f.as_str(), FileFormat::Json))
                    .build()
                    .unwrap()
                    .try_deserialize()
                    .unwrap_or_else(|e| {
                        panic!("!cfg({}): {:?}: {}", p, e, f);
                    })
            })
            .collect()
    }

    fn chain_name_domain_records() -> BTreeSet<ChainCoordinate> {
        hyperlane_settings()
            .iter()
            .flat_map(|x: &Settings| {
                x.chain.chains.iter().map(|(_, v)| ChainCoordinate {
                    name: v.name.clone(),
                    domain: v.domain.parse().unwrap(),
                })
            })
            .collect()
    }

    #[test]
    fn agent_json_config_consistency_checks() {
        // TODO(webbhorn): Also verify with this functionality
        // we have entries for all of the Gelato contract
        // addresses we need hardcoded in the binary for now.

        // Verify that the hard-coded, macro-maintained
        // mapping in `hyperlane-core/src/chain.rs` named
        // by the macro `domain_and_chain` is complete
        // and in agreement with our on-disk json-based
        // configuration data.
        let chain_coords = chain_name_domain_records();
        for ChainCoordinate { name, domain } in chain_coords.iter() {
            assert_eq!(
                HyperlaneDomain::try_from(domain.to_owned())
                    .unwrap()
                    .to_string(),
                name.to_owned()
            );
            assert_eq!(
                u32::from(HyperlaneDomain::from_str(name).unwrap()),
                domain.to_owned()
            );
        }
    }

    #[test]
    fn domain_strings() {
        assert_eq!(
            HyperlaneDomain::from_str("ethereum").unwrap(),
            HyperlaneDomain::Ethereum,
        );
        assert_eq!(
            HyperlaneDomain::Ethereum.to_string(),
            "ethereum".to_string(),
        );
    }

    #[test]
    fn domain_ids() {
        assert_eq!(
            HyperlaneDomain::try_from(0x657468u32).unwrap(),
            HyperlaneDomain::Ethereum,
        );

        assert_eq!(u32::from(HyperlaneDomain::Ethereum), 0x657468u32,);
    }

    #[test]
    fn test_name_from_domain_id() {
        assert_eq!(name_from_domain_id(0x657468u32), Some("ethereum".into()),);

        assert_eq!(name_from_domain_id(0xf00u32), None,);
    }

    #[test]
    fn test_domain_id_from_name() {
        assert_eq!(domain_id_from_name("ethereum"), Some(0x657468u32),);

        assert_eq!(domain_id_from_name("foo"), None,);
    }
}
