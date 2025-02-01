use alloy::primitives::B256;
use serde::{Deserialize, Serialize};
use ssz::Encode;
use ssz_derive::{Decode, Encode};

use crate::{
    types::{
        network::Subnetwork,
        state_trie::{ByteCode, EncodedTrieNode, TrieProof},
    },
    utils::bytes::hex_encode,
    ContentValue, ContentValueError, RawContentValue, StateContentKey,
};

/// A Portal State content value.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum StateContentValue {
    TrieNode(TrieNode),
    AccountTrieNodeWithProof(AccountTrieNodeWithProof),
    ContractStorageTrieNodeWithProof(ContractStorageTrieNodeWithProof),
    ContractBytecode(ContractBytecode),
    ContractBytecodeWithProof(ContractBytecodeWithProof),
}

impl ContentValue for StateContentValue {
    type TContentKey = StateContentKey;

    fn encode(&self) -> RawContentValue {
        match self {
            Self::TrieNode(value) => value.as_ssz_bytes().into(),
            Self::AccountTrieNodeWithProof(value) => value.as_ssz_bytes().into(),
            Self::ContractStorageTrieNodeWithProof(value) => value.as_ssz_bytes().into(),
            Self::ContractBytecode(value) => value.as_ssz_bytes().into(),
            Self::ContractBytecodeWithProof(value) => value.as_ssz_bytes().into(),
        }
    }

    fn decode(key: &Self::TContentKey, buf: &[u8]) -> Result<Self, ContentValueError> {
        let key_type = key.get_content_key_type();

        if let Some(value) = key_type.try_decode_primary(buf) {
            return Ok(value);
        }

        if let Some(value) = key_type.try_decode_proof(buf) {
            return Ok(value);
        }

        Err(ContentValueError::UnknownContent {
            bytes: hex_encode(buf),
            subnetwork: Subnetwork::State,
        })
    }
}

#[derive(Clone, Debug, Decode, Encode, Eq, PartialEq, Serialize, Deserialize)]
pub struct TrieNode {
    pub node: EncodedTrieNode,
}

#[derive(Clone, Debug, Decode, Encode, Eq, PartialEq, Serialize, Deserialize)]
pub struct AccountTrieNodeWithProof {
    pub proof: TrieProof,
    pub block_hash: B256,
}

#[derive(Clone, Debug, Decode, Encode, Eq, PartialEq, Serialize, Deserialize)]
pub struct ContractStorageTrieNodeWithProof {
    pub storage_proof: TrieProof,
    pub account_proof: TrieProof,
    pub block_hash: B256,
}

#[derive(Clone, Debug, Decode, Encode, Eq, PartialEq, Serialize, Deserialize)]
pub struct ContractBytecode {
    pub code: ByteCode,
}

#[derive(Clone, Debug, Decode, Encode, Eq, PartialEq, Serialize, Deserialize)]
pub struct ContractBytecodeWithProof {
    pub code: ByteCode,
    pub account_proof: TrieProof,
    pub block_hash: B256,
}

#[cfg(test)]
mod test {
    use std::path::PathBuf;

    use alloy::primitives::Bytes;
    use anyhow::Result;
    use rstest::rstest;
    use serde::Deserialize;
    use serde_yaml::Value;

    use super::*;
    use crate::test_utils::read_file_from_tests_submodule;

    const TEST_DATA_DIRECTORY: &str = "tests/mainnet/state/serialization";

    #[test]
    fn trie_node() -> Result<()> {
        let value = read_yaml_file("trie_node.yaml")?;
        let expected_content_value = StateContentValue::TrieNode(TrieNode {
            node: yaml_to_bytes(&value["trie_node"]).into(),
        });

        assert_eq!(
            expected_content_value.encode(),
            RawContentValue::deserialize(&value["content_value"])?,
        );

        Ok(())
    }

    #[test]
    fn account_trie_node_with_proof() -> Result<()> {
        let value = read_yaml_file("account_trie_node_with_proof.yaml")?;

        let expected_content_value =
            StateContentValue::AccountTrieNodeWithProof(AccountTrieNodeWithProof {
                proof: yaml_as_proof(&value["proof"]),
                block_hash: B256::deserialize(&value["block_hash"])?,
            });

        assert_eq!(
            expected_content_value.encode(),
            RawContentValue::deserialize(&value["content_value"])?,
        );

        Ok(())
    }

    #[test]
    fn contract_storage_trie_node_with_proof() -> Result<()> {
        let value = read_yaml_file("contract_storage_trie_node_with_proof.yaml")?;

        let expected_content_value =
            StateContentValue::ContractStorageTrieNodeWithProof(ContractStorageTrieNodeWithProof {
                storage_proof: yaml_as_proof(&value["storage_proof"]),
                account_proof: yaml_as_proof(&value["account_proof"]),
                block_hash: B256::deserialize(&value["block_hash"])?,
            });

        assert_eq!(
            expected_content_value.encode(),
            RawContentValue::deserialize(&value["content_value"])?,
        );

        Ok(())
    }

    #[test]
    fn contract_bytecode() -> Result<()> {
        let value = read_yaml_file("contract_bytecode.yaml")?;

        let expected_content_value = StateContentValue::ContractBytecode(ContractBytecode {
            code: yaml_to_bytes(&value["bytecode"]).into(),
        });

        assert_eq!(
            expected_content_value.encode(),
            RawContentValue::deserialize(&value["content_value"])?,
        );

        Ok(())
    }

    #[test]
    fn contract_bytecode_with_proof() -> Result<()> {
        let value = read_yaml_file("contract_bytecode_with_proof.yaml")?;

        let expected_content_value =
            StateContentValue::ContractBytecodeWithProof(ContractBytecodeWithProof {
                code: yaml_to_bytes(&value["bytecode"]).into(),
                account_proof: yaml_as_proof(&value["account_proof"]),
                block_hash: B256::deserialize(&value["block_hash"])?,
            });

        assert_eq!(
            expected_content_value.encode(),
            RawContentValue::deserialize(&value["content_value"])?,
        );

        Ok(())
    }

    #[rstest]
    #[case::trie_node("account_trie_node_key.yaml", "trie_node.yaml")]
    #[case::account_trie_node_with_proof(
        "account_trie_node_key.yaml",
        "account_trie_node_with_proof.yaml"
    )]
    #[case::contract_storage_trie_node_with_proof(
        "contract_storage_trie_node_key.yaml",
        "contract_storage_trie_node_with_proof.yaml"
    )]
    #[case::contract_bytecode("contract_bytecode_key.yaml", "contract_bytecode.yaml")]
    #[case::contract_bytecode_with_proof(
        "contract_bytecode_key.yaml",
        "contract_bytecode_with_proof.yaml"
    )]
    fn encode_decode(#[case] key_filename: &str, #[case] value_filename: &str) -> Result<()> {
        let key_file = read_yaml_file(key_filename)?;
        let key = StateContentKey::deserialize(&key_file["content_key"])?;

        let value = read_yaml_file(value_filename)?;

        let content_value_bytes = RawContentValue::deserialize(&value["content_value"])?;
        let content_value = StateContentValue::decode(&key, &content_value_bytes)?;

        assert_eq!(content_value.encode(), content_value_bytes);
        Ok(())
    }

    #[rstest]
    #[case::trie_node("account_trie_node_key.yaml", "trie_node.yaml")]
    #[case::account_trie_node_with_proof(
        "account_trie_node_key.yaml",
        "account_trie_node_with_proof.yaml"
    )]
    #[case::contract_storage_trie_node_with_proof(
        "contract_storage_trie_node_key.yaml",
        "contract_storage_trie_node_with_proof.yaml"
    )]
    #[case::contract_bytecode("contract_bytecode_key.yaml", "contract_bytecode.yaml")]
    #[case::contract_bytecode_with_proof(
        "contract_bytecode_key.yaml",
        "contract_bytecode_with_proof.yaml"
    )]
    fn hex_str(#[case] key_filename: &str, #[case] value_filename: &str) -> Result<()> {
        let key_file = read_yaml_file(key_filename)?;
        let key = StateContentKey::deserialize(&key_file["content_key"])?;

        let value = read_yaml_file(value_filename)?;
        let content_value_str = String::deserialize(&value["content_value"])?;
        let content_value = StateContentValue::from_hex(&key, &content_value_str)?;

        assert_eq!(content_value.to_hex(), content_value_str);
        Ok(())
    }

    fn read_yaml_file(filename: &str) -> Result<Value> {
        let path = PathBuf::from(TEST_DATA_DIRECTORY).join(filename);
        let file = read_file_from_tests_submodule(path)?;
        Ok(serde_yaml::from_str(&file)?)
    }

    fn yaml_to_bytes(value: &Value) -> Vec<u8> {
        Bytes::deserialize(value).unwrap().to_vec()
    }

    fn yaml_as_proof(value: &Value) -> TrieProof {
        TrieProof::new(
            value
                .as_sequence()
                .unwrap()
                .iter()
                .map(yaml_to_bytes)
                .map(EncodedTrieNode::from)
                .collect(),
        )
        .unwrap()
    }
}
