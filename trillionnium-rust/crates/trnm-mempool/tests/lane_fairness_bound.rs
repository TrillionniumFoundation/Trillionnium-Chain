use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate};

#[path = "lane_fairness_bound/drain_reset.rs"]
mod drain_reset;
#[path = "lane_fairness_bound/normal_latency.rs"]
mod normal_latency;
#[path = "lane_fairness_bound/spillover_and_reserve.rs"]
mod spillover_and_reserve;
