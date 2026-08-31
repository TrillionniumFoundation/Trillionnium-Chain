use anyhow::Result;

use crate::{
    cmd::WalletCommand, derive_address_from_priv_hex, ensure_hex_32_bytes,
    ensure_safe_sign_message, read_key, resolve_wallet_store, sign_message_ed25519, wallet_create,
    write_key, LOCAL_WALLET_WARNING,
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
            eprintln!("{LOCAL_WALLET_WARNING}");
            eprintln!(
                "WARNING: wallet sign produces a development-only offline text signature; it is not a transaction signature, consensus SignIntent, or production authorization."
            );
            let store = resolve_wallet_store(store)?;
            let priv_hex = read_key(&store, &name)?;
            ensure_safe_sign_message(&message)?;
            let (public_key, signature) = sign_message_ed25519(&priv_hex, &message)?;
            let addr = derive_address_from_priv_hex(&priv_hex)?;
            println!("wallet_name={}", name);
            println!("address={}", addr);
            println!("signature_scheme=ed25519");
            println!("signed_bytes=utf8");
            println!("public_key={}", public_key);
            println!("message={}", message);
            println!("signature={}", signature);
        }
    }
    Ok(())
}
