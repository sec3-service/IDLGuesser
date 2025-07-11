use anchor_lang::{
    idl::IdlAccount, prelude::UpgradeableLoaderState, AnchorDeserialize, Discriminator,
};
use anyhow::{anyhow, Result};
use solana_client::rpc_client::RpcClient;
use solana_sdk::{
    account_utils::StateMut, bpf_loader, bpf_loader_deprecated, bpf_loader_upgradeable,
    commitment_config::CommitmentConfig, pubkey::Pubkey,
};
use std::io::Read;

/// Create an RPC client.
pub fn create_client(url: &str) -> RpcClient {
    RpcClient::new_with_commitment(url.to_string(), CommitmentConfig::confirmed())
}

/// Retrieve the program's associated IDL account data and return the deserialized JSON data.
pub fn get_idl_account(client: &RpcClient, program_id: &Pubkey) -> Result<serde_json::Value> {
    let account = client.get_account(&IdlAccount::address(program_id))?;
    if account.data.is_empty() {
        return Err(anyhow!("No IDL account found for program ID: {}", program_id));
    }
    
    let mut d: &[u8] = &account.data[IdlAccount::DISCRIMINATOR.len()..];
    let idl_account: IdlAccount = AnchorDeserialize::deserialize(&mut d)?;

    let compressed_len: usize = idl_account.data_len.try_into().unwrap();
    let compressed_bytes = &account.data[44..44 + compressed_len];
    let mut z = flate2::read::ZlibDecoder::new(compressed_bytes);
    let mut s = Vec::new();
    z.read_to_end(&mut s)?;
    serde_json::from_slice(&s).map_err(Into::into)
}

/// Retrieve the program's executable bytes based on its program ID.
pub fn get_executable(client: &RpcClient, program_id: &Pubkey) -> Result<Vec<u8>> {
    let account = client.get_account(program_id)?;
    if account.owner == bpf_loader_upgradeable::id() {
        match account.state()? {
            UpgradeableLoaderState::Program {
                programdata_address,
            } => {
                let account = client
                    .get_account(&programdata_address)
                    .map_err(|_| anyhow!("Failed to get programdata account"))?;
                let bin =
                    account.data[UpgradeableLoaderState::size_of_programdata_metadata()..].to_vec();
                Ok(bin)
            }
            UpgradeableLoaderState::Buffer { .. } => {
                Ok(account.data[UpgradeableLoaderState::size_of_buffer_metadata()..].to_vec())
            }
            _ => Err(anyhow!("Invalid program id, unknown account state")),
        }
    } else if account.owner == bpf_loader::id() || account.owner == bpf_loader_deprecated::id() {
        Ok(account.data.to_vec())
    } else {
        Err(anyhow!("Invalid program id, unknown program owner"))
    }
}
