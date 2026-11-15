//! Public research material through the original NPQ6 account/task/evaluator owner.
use super::*;
use trnm_crypto_primitives::pon_work;
use trnm_protocol::qualified_work_task::{
    pq_lifecycle_v5::{DemandLeaseV5, TaskRegistrationV5},
    QualifiedWorkTask, TaskPurpose, LOGICAL_MULTIPLY_ADD_UNITS, MATRIX_ARTIFACT_BYTES,
};
impl Application {
    pub fn samples(&self, node: &mut Node) -> Samples {
        let mut packets = Vec::new();
        let mut lease = DemandLeaseV5 {
            slot: 0,
            purpose: TaskPurpose::InferenceContraction,
            network: self.tls.settings.network(),
            parameters: self.tls.settings.parameters(),
            demand_id: [1; 32],
            requester: self.ids[0],
            source: self.ids[1],
            source_record: hash(b"ordinary-public-source-fixture", &[&self.ids[1]]),
            authorization_scope: hash(
                b"ordinary-public-scope-fixture",
                &[&self.ids[0], &self.ids[1]],
            ),
            availability_manifest: [81; 32],
            availability_root: [82; 32],
            generation: 1,
            revision: 1,
            not_before: 1,
            expires: 50,
            available_until: 150,
            cost_class: 1,
        };
        lease.demand_id = lease.derived_demand_id();
        self.append(
            node,
            &mut packets,
            vec![self.signed(0, 1, 18, &lease.encode().unwrap(), None)],
        );
        let a: Vec<u32> = (0..4096).map(|i| ((19 * i + 23) % 271) as u32).collect();
        let b: Vec<u32> = (0..4096).map(|i| ((31 * i + 37) % 277) as u32).collect();
        let model: Vec<u8> = a.iter().flat_map(|n| n.to_le_bytes()).collect();
        let input: Vec<u8> = b.iter().flat_map(|n| n.to_le_bytes()).collect();
        let task = pon_work::task_id(&a, &b).unwrap();
        let model = hash(b"artifact", &[&model]);
        let mut manifest = QualifiedWorkTask {
            purpose: lease.purpose,
            cost_class: 1,
            numeric_encoding: 1,
            hardness_status: 0,
            reuse: 1,
            network: lease.network,
            parameters: lease.parameters,
            work_profile: QualifiedWorkTask::profile_id(),
            source: lease.source,
            demand_id: lease.demand_id,
            source_record: lease.bound_source_record().unwrap(),
            model,
            layer: QualifiedWorkTask::layer_id(model),
            input: hash(b"qualified-task-input-v1", &[&input]),
            recipe: QualifiedWorkTask::recipe_id(),
            matrix_task: task,
            availability_manifest: lease.availability_manifest,
            availability_root: lease.availability_root,
            authorization_scope: lease.authorization_scope,
            withdrawal_head: lease.withdrawal_frontier().unwrap(),
            output_meter: [1; 32],
            rows: 64,
            inner: 64,
            columns: 64,
            demand_nonce: 1,
            not_before: lease.not_before,
            expires: lease.expires,
            available_until: lease.available_until,
            logical_multiply_add_units: LOGICAL_MULTIPLY_ADD_UNITS,
            model_bytes: MATRIX_ARTIFACT_BYTES,
            input_bytes: MATRIX_ARTIFACT_BYTES,
            useful_output_limit: lease.purpose.output_limit(),
        };
        manifest.output_meter = manifest.derived_output_meter();
        let registration = TaskRegistrationV5 {
            lease_id: lease.id().unwrap(),
            prior_statement_id: [0; 32],
            manifest,
        };
        // The original current-role owner, not a fake receipt, rejects an unrelated source.
        let wrong = self.signed(0, 2, 21, &registration.encode().unwrap(), Some(2));
        assert!(node
            .make_consensus_maintenance(
                packets[0].id().unwrap(),
                vec![wrong],
                self.ids[0],
                self.tls.settings.genesis_time() + 52,
                4096
            )
            .is_err());
        self.append(
            node,
            &mut packets,
            vec![self.signed(0, 2, 21, &registration.encode().unwrap(), Some(1))],
        );
        let round = 3 / self.cfg.params["candidate_round_blocks"].as_u64().unwrap();
        let artifact = [41; 32];
        let components = [0; 32];
        let parent = [0; 32];
        let contribution = hash(
            b"contribution-v3",
            &[
                &self.ids[0],
                &self.cfg.family,
                &parent,
                &artifact,
                &components,
                &round.to_le_bytes(),
            ],
        );
        let payload = [
            contribution.as_slice(),
            &self.cfg.family,
            &parent,
            &artifact,
            &32_u64.to_le_bytes(),
            &components,
            &round.to_le_bytes(),
        ]
        .concat();
        self.append(
            node,
            &mut packets,
            vec![self.signed(0, 3, 6, &payload, None)],
        );
        while packets.len() < 15 {
            self.append(node, &mut packets, vec![]);
        }
        let state = node
            .state_at(packets.last().unwrap().id().unwrap())
            .unwrap();
        let evaluation =
            trnm_mvcc_fee::public_evaluation::read_evaluation(&state, contribution).unwrap();
        let round = trnm_mvcc_fee::public_evaluation::round(&evaluation).unwrap();
        let payload = [contribution.as_slice(), &round, &[77; 32]].concat();
        let wrong = self.signed(1, 1, 14, &payload, None);
        assert!(node
            .make_consensus_maintenance(
                packets[14].id().unwrap(),
                vec![wrong],
                self.ids[0],
                self.tls.settings.genesis_time() + 66,
                4096
            )
            .is_err());
        self.append(
            node,
            &mut packets,
            vec![self.signed(2, 1, 14, &payload, None)],
        );
        Samples {
            packets,
            task,
            contribution,
        }
    }

    pub fn assert_task_and_evaluator_state(&self, node: &Node, samples: &Samples) {
        let state = node
            .state_at(samples.packets.last().unwrap().id().unwrap())
            .unwrap();
        let slot = trnm_mvcc_fee::pon_executor::pq_accounts_v2::tasks_v5::slot_key(0).unwrap();
        assert_eq!(state[&slot]["bound_task"], hex::encode(samples.task));
        assert_eq!(state[&slot]["source_sequence"], 1);
        assert_eq!(state[&slot]["registered_height"], 2);
        let evaluation =
            trnm_mvcc_fee::public_evaluation::read_evaluation(&state, samples.contribution)
                .unwrap();
        assert_eq!(evaluation["commits"].as_object().unwrap().len(), 1);
        assert!(evaluation["commits"]
            .get(hex::encode(self.ids[2]))
            .is_some());
        assert_eq!(
            state[&format!("account:{}", hex::encode(self.ids[0]))]["nonce"],
            3
        );
        assert_eq!(
            state[&format!("account:{}", hex::encode(self.ids[1]))]["nonce"],
            0
        );
        assert_eq!(
            state[&format!("account:{}", hex::encode(self.ids[2]))]["nonce"],
            1
        );
    }
}
