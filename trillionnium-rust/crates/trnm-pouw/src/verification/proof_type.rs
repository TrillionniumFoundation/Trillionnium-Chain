#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NormalizationProfile {
    Receipt,
    Registry,
}

pub(crate) fn normalize(raw: &str, profile: NormalizationProfile) -> Option<String> {
    let lowered = raw.trim().to_ascii_lowercase();
    if lowered.is_empty() {
        return None;
    }

    let ascii_compat = lowered
        .chars()
        .map(|ch| match ch {
            '０' => '0',
            '１' => '1',
            '２' => '2',
            '３' => '3',
            '４' => '4',
            '５' => '5',
            '６' => '6',
            '７' => '7',
            '８' => '8',
            '９' => '9',
            _ => ch,
        })
        .collect::<String>();

    let collapsed = ascii_compat
        .split(|ch: char| is_delimiter(ch, profile))
        .filter(|token| !token.is_empty())
        .collect::<Vec<_>>()
        .join(" ");

    if collapsed.is_empty() {
        return None;
    }

    Some(match_alias(&collapsed, profile).to_string())
}

pub(crate) fn normalize_receipt_proof_type(raw: &str) -> String {
    normalize(raw, NormalizationProfile::Receipt).unwrap_or_default()
}

pub(crate) fn normalize_registry_key(raw: &str) -> Option<String> {
    normalize(raw, NormalizationProfile::Registry)
}

fn is_delimiter(ch: char, _profile: NormalizationProfile) -> bool {
    match ch {
        '_' | '＿' | '-' | '－' | '–' | '—' | '―' | '‒' | '−' | '‐' | '‑' | '﹣' | '﹘'
        | '\u{200b}' | '\u{200c}' | '\u{200d}' | '\u{2060}' | '\u{2061}' | '\u{2062}'
        | '\u{2063}' | '\u{feff}' | '/' | '／' | '⁄' | '.' | ':' | '：' | '+' | '＋' | '|'
        | '｜' | '\\' | '＼' | ',' | '，' | '、' | ';' | '；' | '。' | '．' | '·' | '・' | '∙'
        | '⋅' | '=' | '@' | '#' | '`' | '%' | '$' | '&' | '(' | ')' | '（' | '）' | '[' | ']'
        | '［' | '］' | '{' | '}' | '｛' | '｝' | '<' | '>' | '"' | '\'' | '“' | '”' | '‘'
        | '’' | '!' | '！' | '?' | '？' | '*' | '~' | '～' | '〜' | '^' | '®' | '™' => {
            true
        }
        '\u{00a0}' | '\u{00ad}' | '\u{3000}' | '\u{180e}' => true,
        _ => ch.is_whitespace(),
    }
}

fn match_alias<'a>(collapsed: &'a str, profile: NormalizationProfile) -> &'a str {
    match collapsed {
        "fraud proof"
        | "fraud receipt"
        | "fraud challenge"
        | "fraud proof v1"
        | "fraud proof v2"
        | "fraud proof v3"
        | "fraud proof v 1"
        | "fraud proof v 2"
        | "fraud proof v 3"
        | "fraud receipt v1"
        | "fraud receipt v2"
        | "fraud receipt v 1"
        | "fraud receipt v 2"
        | "fraud receipt v3"
        | "fraud receipt v 3"
        | "fraud challenge v1"
        | "fraud challenge v2"
        | "fraud challenge v3"
        | "fraud challenge v 1"
        | "fraud challenge v 2"
        | "fraud challenge v 3"
        | "fraud receiptv1"
        | "fraud receiptv2"
        | "fraud receiptv3"
        | "fraud challengev1"
        | "fraud challengev2"
        | "fraud challengev3"
        | "fraudproof"
        | "fraudproofv1"
        | "fraudproofv2"
        | "fraudproofv3"
        | "fraudreceipt"
        | "fraudreceiptv1"
        | "fraudreceiptv2"
        | "fraudreceiptv3"
        | "fraudchallenge"
        | "fraudchallengev1"
        | "fraudchallengev2"
        | "fraudchallengev3" => "fraud",

        "tee proof"
        | "tee receipt"
        | "tee proof v1"
        | "tee proof v2"
        | "tee proof v3"
        | "tee proof v 1"
        | "tee proof v 2"
        | "tee proof v 3"
        | "tee receipt v1"
        | "tee receipt v2"
        | "tee receipt v3"
        | "tee receiptv1"
        | "tee receiptv2"
        | "tee receiptv3"
        | "tee receipt v 1"
        | "tee receipt v 2"
        | "tee receipt v 3"
        | "tee attestation"
        | "tee attestation v1"
        | "tee attestation v2"
        | "tee attestation v3"
        | "tee attestation v 1"
        | "tee attestation v 2"
        | "tee attestation v 3"
        | "tee quote"
        | "tee quote v1"
        | "tee quote v2"
        | "tee quote v3"
        | "tee quote v 1"
        | "tee quote v 2"
        | "tee quote v 3"
        | "tee report"
        | "tee report v1"
        | "tee report v2"
        | "tee report v3"
        | "tee report v 1"
        | "tee report v 2"
        | "tee report v 3"
        | "sgx quote"
        | "sgx quote v1"
        | "sgx quote v2"
        | "sgx quote v3"
        | "sgx quote v 1"
        | "sgx quote v 2"
        | "sgx quote v 3"
        | "enclave quote"
        | "sgx report"
        | "sgx report v1"
        | "sgx report v2"
        | "sgx report v3"
        | "sgx report v 1"
        | "sgx report v 2"
        | "sgx report v 3"
        | "tee evidence"
        | "remote attestation"
        | "remote attestation report"
        | "remote attestation quote"
        | "remote attestation receipt"
        | "remote attestation evidence"
        | "tee remote attestation report"
        | "tee remote attestation quote"
        | "tee remote attestation receipt"
        | "tee remote attestation evidence"
        | "attestation report"
        | "attestation report v1"
        | "attestation report v2"
        | "attestation report v3"
        | "attestation report v 1"
        | "attestation report v 2"
        | "attestation report v 3"
        | "tee attestation report"
        | "tee attestation report v1"
        | "tee attestation report v2"
        | "tee attestation report v3"
        | "tee attestation report v 1"
        | "tee attestation report v 2"
        | "tee attestation report v 3"
        | "ra report"
        | "ra report v1"
        | "ra report v2"
        | "ra report v3"
        | "ra report v 1"
        | "ra report v 2"
        | "ra report v 3"
        | "ra quote"
        | "ra quote v1"
        | "ra quote v2"
        | "ra quote v3"
        | "ra quote v 1"
        | "ra quote v 2"
        | "ra quote v 3"
        | "dcap quote"
        | "intel dcap quote"
        | "sgx dcap quote"
        | "intel sgx dcap quote"
        | "tdx quote"
        | "td quote"
        | "tdx report"
        | "td report"
        | "snp report"
        | "snp quote"
        | "sev snp report"
        | "sev snp quote"
        | "amd sev snp report"
        | "amd sev snp quote"
        | "intel tdx quote"
        | "tee cert"
        | "tee certificate"
        | "teeproof"
        | "teeproofv1"
        | "teeproofv2"
        | "teeproofv3"
        | "teereceipt"
        | "teereceiptv1"
        | "teereceiptv2"
        | "teereceiptv3"
        | "teeattestation"
        | "teeattestationv1"
        | "teeattestationv2"
        | "teeattestationv3"
        | "teequote"
        | "teequotev1"
        | "teequotev2"
        | "teequotev3"
        | "teereport"
        | "teereportv1"
        | "teereportv2"
        | "teereportv3"
        | "sgxquote"
        | "sgxquotev1"
        | "sgxquotev2"
        | "sgxquotev3"
        | "enclavequote"
        | "sgxreport"
        | "sgxreportv1"
        | "sgxreportv2"
        | "sgxreportv3"
        | "teeevidence"
        | "remoteattestation"
        | "attestationreport"
        | "attestationreportv1"
        | "attestationreportv2"
        | "attestationreportv3"
        | "teeattestationreport"
        | "teeattestationreportv1"
        | "teeattestationreportv2"
        | "teeattestationreportv3"
        | "rareport"
        | "rareportv1"
        | "rareportv2"
        | "rareportv3"
        | "raquote"
        | "raquotev1"
        | "raquotev2"
        | "raquotev3"
        | "dcapquote"
        | "inteldcapquote"
        | "sgxdcapquote"
        | "intelsgxdcapquote"
        | "tdxquote"
        | "tdquote"
        | "tdxreport"
        | "tdreport"
        | "snpreport"
        | "snpquote"
        | "sevsnpreport"
        | "sevsnpquote"
        | "amdsevsnpreport"
        | "amdsevsnpquote"
        | "inteltdxquote"
        | "teecert"
        | "teecertificate" => "tee",

        "zk proof"
        | "zk receipt"
        | "zk proof v1"
        | "zk proof v2"
        | "zk proof v3"
        | "zk proof v 1"
        | "zk proof v 2"
        | "zk proof v 3"
        | "zk receipt v1"
        | "zk receipt v2"
        | "zk receipt v3"
        | "zk receiptv1"
        | "zk receiptv2"
        | "zk receiptv3"
        | "zk receipt v 1"
        | "zk receipt v 2"
        | "zk receipt v 3"
        | "zk attestation"
        | "zk evidence"
        | "zk snark"
        | "snark"
        | "zero knowledge"
        | "zero knowledge proof"
        | "zero knowledge proof v1"
        | "zero knowledge proof v2"
        | "zero knowledge proof v3"
        | "zero knowledge proof v 1"
        | "zero knowledge proof v 2"
        | "zero knowledge proof v 3"
        | "zero knowledge receipt"
        | "zero knowledge receipt v1"
        | "zero knowledge receipt v2"
        | "zero knowledge receipt v3"
        | "zero knowledge receipt v 1"
        | "zero knowledge receipt v 2"
        | "zero knowledge receipt v 3"
        | "zero knowledge receiptv1"
        | "zero knowledge receiptv2"
        | "zero knowledge receiptv3"
        | "zero knowledge certificate"
        | "zero knowledge attestation"
        | "zero knowledge evidence"
        | "zero knowledge snark"
        | "zkproof"
        | "zkproofv1"
        | "zkproofv2"
        | "zkproofv3"
        | "zkreceipt"
        | "zkreceiptv1"
        | "zkreceiptv2"
        | "zkreceiptv3"
        | "zkattestation"
        | "zkevidence"
        | "zksnark"
        | "zkp"
        | "zk p"
        | "zeroknowledge"
        | "zeroknowledgesnark"
        | "zeroknowledgeproof"
        | "zeroknowledgeproofv1"
        | "zeroknowledgeproofv2"
        | "zeroknowledgeproofv3"
        | "zeroknowledgereceipt"
        | "zeroknowledgereceiptv1"
        | "zeroknowledgereceiptv2"
        | "zeroknowledgereceiptv3"
        | "zeroknowledgecertificate"
        | "zeroknowledgeattestation"
        | "zeroknowledgeevidence"
        | "zk cert"
        | "zkcert" => "zk",

        _ => {
            if matches!(profile, NormalizationProfile::Registry) {
                match collapsed {
                    "remote attestation v1"
                    | "remoteattestationv1"
                    | "remote attestation v 1"
                    | "remote attestation v2"
                    | "remoteattestationv2"
                    | "remote attestation v 2"
                    | "remote attestation v3"
                    | "remoteattestationv3"
                    | "remote attestation v 3" => "tee",
                    _ => collapsed,
                }
            } else {
                collapsed
            }
        }
    }
}
