use super::*;

#[test]
fn settlement_evidence_path_encodes_dual_chain_route_and_state() {
    let rec = SettlementRecord {
        settlement_id: 42,
        route: BridgeRoute {
            route_id: "eth->trnm".to_string(),
            source_chain: "ethereum".to_string(),
            target_chain: "trillionnium".to_string(),
        },
        status: SettlementStatus::Pending,
        at_height: 900,
        settlement_tx: None,
        revert_reason: None,
    };

    assert_eq!(
        rec.evidence_path(),
        "settlements/eth->trnm/ethereum/trillionnium/42/pending@900"
    );
}

#[test]
fn settlement_evidence_path_tracks_terminal_state_machine_outcome() {
    let mut rec = SettlementRecord {
        settlement_id: 43,
        route: BridgeRoute {
            route_id: "eth->trnm".to_string(),
            source_chain: "ethereum".to_string(),
            target_chain: "trillionnium".to_string(),
        },
        status: SettlementStatus::Pending,
        at_height: 1_000,
        settlement_tx: None,
        revert_reason: None,
    };

    rec.apply_status(
        SettlementStatus::Finalized,
        1_001,
        Some("0xsettled".to_string()),
        None,
    )
    .unwrap();
    assert_eq!(
        rec.evidence_path(),
        "settlements/eth->trnm/ethereum/trillionnium/43/finalized@1001"
    );

    let mut rec_reverted = SettlementRecord {
        settlement_id: 44,
        route: BridgeRoute {
            route_id: "eth->trnm".to_string(),
            source_chain: "ethereum".to_string(),
            target_chain: "trillionnium".to_string(),
        },
        status: SettlementStatus::Pending,
        at_height: 2_000,
        settlement_tx: None,
        revert_reason: None,
    };

    rec_reverted
        .apply_status(
            SettlementStatus::Reverted,
            2_001,
            None,
            Some("proof_mismatch".to_string()),
        )
        .unwrap();
    assert_eq!(
        rec_reverted.evidence_path(),
        "settlements/eth->trnm/ethereum/trillionnium/44/reverted@2001"
    );
}

#[test]
fn settlement_evidence_path_sanitizes_route_segments_for_filesystem_safety() {
    let rec = SettlementRecord {
        settlement_id: 45,
        route: BridgeRoute {
            route_id: "eth/mainnet -> trnm".to_string(),
            source_chain: "ethereum/mainnet".to_string(),
            target_chain: "trillionnium\nalpha".to_string(),
        },
        status: SettlementStatus::Pending,
        at_height: 2_222,
        settlement_tx: None,
        revert_reason: None,
    };

    assert_eq!(
        rec.evidence_path(),
        "settlements/eth_mainnet_->_trnm/ethereum_mainnet/trillionnium_alpha/45/pending@2222"
    );
}

#[test]
fn settlement_evidence_path_replaces_empty_route_segments_with_placeholder() {
    let rec = SettlementRecord {
        settlement_id: 46,
        route: BridgeRoute {
            route_id: "   ".to_string(),
            source_chain: "\n\t".to_string(),
            target_chain: "".to_string(),
        },
        status: SettlementStatus::Pending,
        at_height: 2_223,
        settlement_tx: None,
        revert_reason: None,
    };

    assert_eq!(rec.evidence_path(), "settlements/_/_/_/46/pending@2223");
}

#[test]
fn settlement_evidence_path_rewrites_dot_segments_to_placeholder() {
    let rec = SettlementRecord {
        settlement_id: 47,
        route: BridgeRoute {
            route_id: "..".to_string(),
            source_chain: ".".to_string(),
            target_chain: "trillionnium".to_string(),
        },
        status: SettlementStatus::Pending,
        at_height: 2_224,
        settlement_tx: None,
        revert_reason: None,
    };

    assert_eq!(
        rec.evidence_path(),
        "settlements/_/_/trillionnium/47/pending@2224"
    );
}

#[test]
fn settlement_evidence_path_sanitizes_windows_separators_and_control_whitespace() {
    let rec = SettlementRecord {
        settlement_id: 48,
        route: BridgeRoute {
            route_id: "eth\\mainnet\t->\ttrnm".to_string(),
            source_chain: "ethereum\\mainnet".to_string(),
            target_chain: "trillionnium\ralpha".to_string(),
        },
        status: SettlementStatus::Pending,
        at_height: 2_225,
        settlement_tx: None,
        revert_reason: None,
    };

    assert_eq!(
        rec.evidence_path(),
        "settlements/eth_mainnet_->_trnm/ethereum_mainnet/trillionnium_alpha/48/pending@2225"
    );
}

#[test]
fn settlement_evidence_path_sanitizes_unicode_whitespace_segments() {
    let rec = SettlementRecord {
        settlement_id: 480,
        route: BridgeRoute {
            route_id: "eth\u{2003}mainnet->trnm".to_string(),
            source_chain: "ethereum\u{00A0}mainnet".to_string(),
            target_chain: "trillionnium\u{3000}alpha".to_string(),
        },
        status: SettlementStatus::Pending,
        at_height: 2_225,
        settlement_tx: None,
        revert_reason: None,
    };

    assert_eq!(
        rec.evidence_path(),
        "settlements/eth_mainnet->trnm/ethereum_mainnet/trillionnium_alpha/480/pending@2225"
    );
}

#[test]
fn settlement_evidence_path_sanitizes_bidi_and_zero_width_format_controls() {
    let rec = SettlementRecord {
        settlement_id: 481,
        route: BridgeRoute {
            route_id: "eth\u{202E}mainnet->trnm\u{200B}".to_string(),
            source_chain: "ethereum\u{2066}mainnet\u{2069}".to_string(),
            target_chain: "trillionnium\u{FEFF}alpha".to_string(),
        },
        status: SettlementStatus::Pending,
        at_height: 2_225,
        settlement_tx: None,
        revert_reason: None,
    };

    assert_eq!(
        rec.evidence_path(),
        "settlements/eth_mainnet->trnm_/ethereum_mainnet_/trillionnium_alpha/481/pending@2225"
    );
}

#[test]
fn settlement_evidence_path_sanitizes_colon_for_cross_platform_filesystem_safety() {
    let rec = SettlementRecord {
        settlement_id: 49,
        route: BridgeRoute {
            route_id: "eth:mainnet->trnm".to_string(),
            source_chain: "ethereum:mainnet".to_string(),
            target_chain: "trillionnium:alpha".to_string(),
        },
        status: SettlementStatus::Pending,
        at_height: 2_226,
        settlement_tx: None,
        revert_reason: None,
    };

    assert_eq!(
        rec.evidence_path(),
        "settlements/eth_mainnet->trnm/ethereum_mainnet/trillionnium_alpha/49/pending@2226"
    );
}

#[test]
fn settlement_evidence_path_sanitizes_arabic_letter_mark_controls() {
    let rec = SettlementRecord {
        settlement_id: 49_1,
        route: BridgeRoute {
            route_id: "eth\u{061C}mainnet->trnm".to_string(),
            source_chain: "ethereum\u{061C}mainnet".to_string(),
            target_chain: "trillionnium\u{061C}alpha".to_string(),
        },
        status: SettlementStatus::Pending,
        at_height: 2_226,
        settlement_tx: None,
        revert_reason: None,
    };

    assert_eq!(
        rec.evidence_path(),
        "settlements/eth_mainnet->trnm/ethereum_mainnet/trillionnium_alpha/491/pending@2226"
    );
}

#[test]
fn settlement_evidence_path_sanitizes_word_joiner_controls() {
    let rec = SettlementRecord {
        settlement_id: 49_2,
        route: BridgeRoute {
            route_id: "eth\u{2060}mainnet->trnm".to_string(),
            source_chain: "ethereum\u{2060}mainnet".to_string(),
            target_chain: "trillionnium\u{2060}alpha".to_string(),
        },
        status: SettlementStatus::Pending,
        at_height: 2_226,
        settlement_tx: None,
        revert_reason: None,
    };

    assert_eq!(
        rec.evidence_path(),
        "settlements/eth_mainnet->trnm/ethereum_mainnet/trillionnium_alpha/492/pending@2226"
    );
}

#[test]
fn settlement_evidence_path_sanitizes_windows_reserved_punctuation() {
    let rec = SettlementRecord {
        settlement_id: 50,
        route: BridgeRoute {
            route_id: "eth<mainnet>|trnm".to_string(),
            source_chain: "ethereum?mainnet".to_string(),
            target_chain: "trillionnium\"alpha*".to_string(),
        },
        status: SettlementStatus::Pending,
        at_height: 2_227,
        settlement_tx: None,
        revert_reason: None,
    };

    assert_eq!(
        rec.evidence_path(),
        "settlements/eth_mainnet>_trnm/ethereum_mainnet/trillionnium_alpha_/50/pending@2227"
    );
}

#[test]
fn settlement_evidence_path_avoids_windows_reserved_device_names() {
    let rec = SettlementRecord {
        settlement_id: 51,
        route: BridgeRoute {
            route_id: "CON".to_string(),
            source_chain: "nul".to_string(),
            target_chain: "Com1".to_string(),
        },
        status: SettlementStatus::Pending,
        at_height: 2_228,
        settlement_tx: None,
        revert_reason: None,
    };

    assert_eq!(
        rec.evidence_path(),
        "settlements/CON_/nul_/Com1_/51/pending@2228"
    );
}

#[test]
fn settlement_evidence_path_avoids_windows_reserved_device_names_with_extension_alias() {
    let rec = SettlementRecord {
        settlement_id: 52,
        route: BridgeRoute {
            route_id: "con.txt".to_string(),
            source_chain: "LPT1.log".to_string(),
            target_chain: "aux.backup".to_string(),
        },
        status: SettlementStatus::Pending,
        at_height: 2_229,
        settlement_tx: None,
        revert_reason: None,
    };

    assert_eq!(
        rec.evidence_path(),
        "settlements/con.txt_/LPT1.log_/aux.backup_/52/pending@2229"
    );
}

#[test]
fn settlement_evidence_path_avoids_windows_reserved_device_names_with_trailing_dot_or_space() {
    let rec = SettlementRecord {
        settlement_id: 53,
        route: BridgeRoute {
            route_id: "CON. ".to_string(),
            source_chain: "lpt1...".to_string(),
            target_chain: "aux ".to_string(),
        },
        status: SettlementStatus::Pending,
        at_height: 2_230,
        settlement_tx: None,
        revert_reason: None,
    };

    assert_eq!(
        rec.evidence_path(),
        "settlements/CON_/lpt1_/aux_/53/pending@2230"
    );
}

#[test]
fn settlement_evidence_path_avoids_windows_reserved_device_names_with_unicode_space_padding() {
    let rec = SettlementRecord {
        settlement_id: 53_0,
        route: BridgeRoute {
            route_id: "\u{2003}CON\u{2002}".to_string(),
            source_chain: "\u{00A0}nul\u{00A0}".to_string(),
            target_chain: "\u{2009}LPT9\u{2009}".to_string(),
        },
        status: SettlementStatus::Pending,
        at_height: 2_229,
        settlement_tx: None,
        revert_reason: None,
    };

    assert_eq!(
        rec.evidence_path(),
        "settlements/CON_/nul_/LPT9_/530/pending@2229"
    );
}

#[test]
fn settlement_evidence_path_trims_trailing_dot_or_space_for_non_reserved_segments() {
    let rec = SettlementRecord {
        settlement_id: 53_1,
        route: BridgeRoute {
            route_id: "eth-mainnet. ".to_string(),
            source_chain: "ethereum.. ".to_string(),
            target_chain: "trillionnium-alpha ".to_string(),
        },
        status: SettlementStatus::Pending,
        at_height: 2_230,
        settlement_tx: None,
        revert_reason: None,
    };

    assert_eq!(
        rec.evidence_path(),
        "settlements/eth-mainnet/ethereum/trillionnium-alpha/531/pending@2230"
    );
}

#[test]
fn settlement_evidence_path_sanitizes_nested_path_aliases_without_false_reserved_suffixes() {
    let rec = SettlementRecord {
        settlement_id: 54,
        route: BridgeRoute {
            route_id: "eth/CON/log".to_string(),
            source_chain: "bridge\\aux.txt".to_string(),
            target_chain: "mainnet/Com9.trace".to_string(),
        },
        status: SettlementStatus::Pending,
        at_height: 2_231,
        settlement_tx: None,
        revert_reason: None,
    };

    assert_eq!(
        rec.evidence_path(),
        "settlements/eth_CON_log/bridge_aux.txt/mainnet_Com9.trace/54/pending@2231"
    );
}

#[test]
fn settlement_evidence_path_sanitizes_nested_reserved_device_aliases_with_trailing_dot_or_space() {
    let rec = SettlementRecord {
        settlement_id: 55,
        route: BridgeRoute {
            route_id: "eth/CON. /log".to_string(),
            source_chain: "bridge\\aux...\\proof".to_string(),
            target_chain: "mainnet/LPT1 .trace".to_string(),
        },
        status: SettlementStatus::Pending,
        at_height: 2_232,
        settlement_tx: None,
        revert_reason: None,
    };

    assert_eq!(
        rec.evidence_path(),
        "settlements/eth_CON.__log/bridge_aux..._proof/mainnet_LPT1_.trace/55/pending@2232"
    );
}
