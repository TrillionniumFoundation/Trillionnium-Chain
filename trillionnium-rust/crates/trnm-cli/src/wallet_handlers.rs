use anyhow::Result;

use crate::{
    cmd::WalletCommand, derive_address_from_priv_hex, ensure_hex_32_bytes,
    ensure_safe_sign_message, hash, read_key, resolve_wallet_store, wallet_create, write_key,
};

pub(crate) fn handle_wallet_command(wallet: WalletCommand) -> Result<()> {
    match wallet {
        WalletCommand::Create { name, out } | WalletCommand::Generate { name, out } => {
            wallet_create(name, out)?;
        }
        WalletCommand::Import {
            name,
            private_key_hex,
            out,
        } => {
            let store = resolve_wallet_store(out)?;
            let priv_hex = ensure_hex_32_bytes(&private_key_hex)?;
            let path = write_key(&store, &name, &priv_hex)?;
            let addr = derive_address_from_priv_hex(&priv_hex)?;
            println!("wallet_name={}", name);
            println!("wallet_path={}", path.display());
            println!("address={}", addr);
        }
        WalletCommand::Address { name, store } => {
            let store = resolve_wallet_store(store)?;
            let priv_hex = read_key(&store, &name)?;
            let addr = derive_address_from_priv_hex(&priv_hex)?;
            println!("wallet_name={}", name);
            println!("address={}", addr);
        }
        WalletCommand::Sign {
            name,
            message,
            store,
        } => {
            let store = resolve_wallet_store(store)?;
            let priv_hex = read_key(&store, &name)?;
            ensure_safe_sign_message(&message)?;
            let sig = hash(&["trnm-sign-v1", &priv_hex, &message]);
            let addr = derive_address_from_priv_hex(&priv_hex)?;
            println!("wallet_name={}", name);
            println!("address={}", addr);
            println!("message={}", message);
            println!("signature={}", sig);
        }
    }
    Ok(())
}
