use crate::{is_idempotent_duplicate_ok, is_invisible_filler, AdapterExecResult};

fn is_receipt_quote_wrapper(ch: char) -> bool {
    matches!(
        ch,
        '"' | '\''
            | '`'
            | '“'
            | '”'
            | '‘'
            | '’'
            | '«'
            | '»'
            | '‹'
            | '›'
            | '〈'
            | '〉'
            | '《'
            | '》'
            | '⟨'
            | '⟩'
            | '「'
            | '」'
            | '『'
            | '』'
    )
}

fn normalize_candidate_tx_hash(raw: &str) -> Option<String> {
    let cleaned = raw
        .trim_matches(|c: char| {
            is_receipt_quote_wrapper(c)
                || matches!(
                    c,
                    ',' | ';' | '.' | ':' | ')' | ']' | '}' | '>' | '(' | '[' | '{' | '<'
                )
                || c.is_control()
                || is_invisible_filler(c)
        })
        .trim_end_matches(|c: char| {
            is_receipt_quote_wrapper(c)
                || matches!(c, ',' | ';' | '}' | ']' | '>')
                || c.is_control()
                || is_invisible_filler(c)
        })
        .trim();
    let normalized = cleaned
        .strip_prefix("0x")
        .or_else(|| cleaned.strip_prefix("0X"))
        .unwrap_or(cleaned);

    if normalized.len() >= 8
        && normalized.len() <= 128
        && normalized.chars().all(|c| c.is_ascii_hexdigit())
    {
        Some(normalized.to_ascii_lowercase())
    } else {
        None
    }
}

pub(crate) fn parse_tx_hash(text: &str) -> Option<String> {
    const PREFIXES: &[&str] = &[
        "tx_hash=",
        "tx_hash =",
        "tx_hash:",
        "tx_hash :",
        "TX_HASH=",
        "TX_HASH =",
        "TX_HASH:",
        "TX_HASH :",
        "tx-hash=",
        "tx-hash =",
        "tx-hash:",
        "tx-hash :",
        "TX-HASH=",
        "TX-HASH =",
        "TX-HASH:",
        "TX-HASH :",
        "tx hash=",
        "tx hash =",
        "tx hash:",
        "tx hash :",
        "TX HASH=",
        "TX HASH =",
        "TX HASH:",
        "TX HASH :",
        "txHash=",
        "txHash =",
        "txHash:",
        "txHash :",
        "TXHASH=",
        "TXHASH =",
        "TXHASH:",
        "TXHASH :",
        "txhash=",
        "txhash =",
        "txhash:",
        "txhash :",
        "transaction_hash=",
        "transaction_hash =",
        "transaction_hash:",
        "transaction_hash :",
        "TRANSACTION_HASH=",
        "TRANSACTION_HASH =",
        "TRANSACTION_HASH:",
        "TRANSACTION_HASH :",
        "transaction-hash=",
        "transaction-hash =",
        "transaction-hash:",
        "transaction-hash :",
        "TRANSACTION-HASH=",
        "TRANSACTION-HASH =",
        "TRANSACTION-HASH:",
        "TRANSACTION-HASH :",
        "transaction hash=",
        "transaction hash =",
        "transaction hash:",
        "transaction hash :",
        "TRANSACTION HASH=",
        "TRANSACTION HASH =",
        "TRANSACTION HASH:",
        "TRANSACTION HASH :",
        "transactionHash=",
        "transactionHash =",
        "transactionHash:",
        "transactionHash :",
        "TRANSACTIONHASH=",
        "TRANSACTIONHASH =",
        "TRANSACTIONHASH:",
        "TRANSACTIONHASH :",
        "transactionhash=",
        "transactionhash =",
        "transactionhash:",
        "transactionhash :",
        "\"tx_hash\":",
        "\"tx_hash\" :",
        "\"TX_HASH\":",
        "\"TX_HASH\" :",
        "\"tx-hash\":",
        "\"tx-hash\" :",
        "\"TX-HASH\":",
        "\"TX-HASH\" :",
        "\"tx hash\":",
        "\"tx hash\" :",
        "\"TX HASH\":",
        "\"TX HASH\" :",
        "\"txHash\":",
        "\"txHash\" :",
        "\"TXHASH\":",
        "\"TXHASH\" :",
        "\"txhash\":",
        "\"txhash\" :",
        "\"transaction_hash\":",
        "\"transaction_hash\" :",
        "\"TRANSACTION_HASH\":",
        "\"TRANSACTION_HASH\" :",
        "\"transaction-hash\":",
        "\"transaction-hash\" :",
        "\"TRANSACTION-HASH\":",
        "\"TRANSACTION-HASH\" :",
        "\"transaction hash\":",
        "\"transaction hash\" :",
        "\"TRANSACTION HASH\":",
        "\"TRANSACTION HASH\" :",
        "\"transactionHash\":",
        "\"transactionHash\" :",
        "\"TRANSACTIONHASH\":",
        "\"TRANSACTIONHASH\" :",
        "\"transactionhash\":",
        "\"transactionhash\" :",
        "'tx_hash':",
        "'tx_hash' :",
        "'TX_HASH':",
        "'TX_HASH' :",
        "'tx-hash':",
        "'tx-hash' :",
        "'TX-HASH':",
        "'TX-HASH' :",
        "'tx hash':",
        "'tx hash' :",
        "'TX HASH':",
        "'TX HASH' :",
        "'txHash':",
        "'txHash' :",
        "'TXHASH':",
        "'TXHASH' :",
        "'txhash':",
        "'txhash' :",
        "'transaction_hash':",
        "'transaction_hash' :",
        "'TRANSACTION_HASH':",
        "'TRANSACTION_HASH' :",
        "'transaction-hash':",
        "'transaction-hash' :",
        "'TRANSACTION-HASH':",
        "'TRANSACTION-HASH' :",
        "'transaction hash':",
        "'transaction hash' :",
        "'TRANSACTION HASH':",
        "'TRANSACTION HASH' :",
        "'transactionHash':",
        "'transactionHash' :",
        "'TRANSACTIONHASH':",
        "'TRANSACTIONHASH' :",
        "'transactionhash':",
        "'transactionhash' :",
    ];

    fn parse_hash_from_suffix(suffix: &str) -> Option<String> {
        let trimmed = suffix.trim_start();
        if trimmed.is_empty() {
            return None;
        }

        let mut candidate = trimmed;
        loop {
            let before = candidate;
            candidate = candidate.trim_start_matches(|ch: char| {
                ch.is_ascii_whitespace()
                    || ch.is_control()
                    || is_invisible_filler(ch)
                    || is_receipt_quote_wrapper(ch)
                    || matches!(ch, '(' | '[' | '{' | '<')
            });
            if let Some(rest) = candidate.strip_prefix('\\') {
                if rest.chars().next().is_some_and(is_receipt_quote_wrapper) {
                    candidate = rest;
                    continue;
                }
            }
            if candidate == before {
                break;
            }
        }
        if candidate.is_empty() {
            return None;
        }

        let candidate_end = candidate
            .char_indices()
            .find_map(|(idx, ch)| {
                let is_hash_char = ch.is_ascii_hexdigit()
                    || matches!(ch, 'x' | 'X')
                    || is_receipt_quote_wrapper(ch);
                (!is_hash_char).then_some(idx)
            })
            .unwrap_or(candidate.len());

        normalize_candidate_tx_hash(&candidate[..candidate_end])
    }

    let mut normalized_key_quotes = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\\' && chars.peek().copied().is_some_and(is_receipt_quote_wrapper) {
            continue;
        }
        if is_receipt_quote_wrapper(ch) {
            normalized_key_quotes.push('"');
        } else {
            normalized_key_quotes.push(ch);
        }
    }
    let normalized_delimiters = normalized_key_quotes
        .chars()
        .map(|ch| match ch {
            '：' => ':',
            '＝' => '=',
            '‐' | '‑' | '‒' | '–' | '—' | '―' | '−' | '－' => '-',
            other => other,
        })
        .collect::<String>();
    let mut normalized_whitespace = String::with_capacity(normalized_delimiters.len());
    let mut last_was_space = false;
    for ch in normalized_delimiters.chars() {
        if ch.is_whitespace() {
            if !last_was_space {
                normalized_whitespace.push(' ');
                last_was_space = true;
            }
        } else {
            normalized_whitespace.push(ch);
            last_was_space = false;
        }
    }

    for haystack in [
        text,
        normalized_key_quotes.as_str(),
        normalized_delimiters.as_str(),
        normalized_whitespace.as_str(),
    ] {
        for prefix in PREFIXES {
            let mut remainder = haystack;
            while let Some(idx) = remainder.find(prefix) {
                let suffix = &remainder[idx + prefix.len()..];
                if let Some(parsed) = parse_hash_from_suffix(suffix) {
                    return Some(parsed);
                }
                remainder = &suffix[1.min(suffix.len())..];
            }
        }
    }

    text.split_whitespace().find_map(|w| {
        PREFIXES
            .iter()
            .find_map(|prefix| w.strip_prefix(prefix))
            .and_then(normalize_candidate_tx_hash)
    })
}

pub(crate) fn should_execute_reveal(commit_res: &AdapterExecResult) -> bool {
    commit_res.ok || is_idempotent_duplicate_ok(commit_res.rc)
}
