use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use trnm_types::{Hash32, ObjectRef, TaskObject};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObjectValue {
    Task(TaskObject),
}

#[derive(Debug, Default, Clone)]
pub struct StateStore {
    objects: BTreeMap<u64, VersionedObject>,
}

#[derive(Debug, Clone)]
struct VersionedObject {
    version: u64,
    value: ObjectValue,
}

impl StateStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get_ref(&self, id: u64) -> Option<ObjectRef> {
        self.objects.get(&id).map(|v| ObjectRef { id, version: v.version })
    }

    pub fn get_task(&self, id: u64) -> Option<TaskObject> {
        self.objects.get(&id).and_then(|v| match &v.value {
            ObjectValue::Task(t) => Some(t.clone()),
        })
    }

    pub fn put_task_new(&mut self, task: TaskObject) -> Result<ObjectRef, String> {
        if self.objects.contains_key(&task.task_id) {
            return Err("task already exists".into());
        }
        let id = task.task_id;
        self.objects.insert(
            id,
            VersionedObject {
                version: 1,
                value: ObjectValue::Task(task),
            },
        );
        Ok(ObjectRef { id, version: 1 })
    }

    pub fn update_task(
        &mut self,
        expected: ObjectRef,
        mut task: TaskObject,
    ) -> Result<ObjectRef, String> {
        let current = self
            .objects
            .get(&expected.id)
            .ok_or_else(|| "object not found".to_string())?;
        if current.version != expected.version {
            return Err("version conflict".into());
        }
        let new_version = current.version + 1;
        task.version = new_version;
        self.objects.insert(
            expected.id,
            VersionedObject {
                version: new_version,
                value: ObjectValue::Task(task),
            },
        );
        Ok(ObjectRef {
            id: expected.id,
            version: new_version,
        })
    }

    pub fn state_root(&self) -> Hash32 {
        let mut hasher = Sha256::new();
        for (id, v) in &self.objects {
            hasher.update(id.to_le_bytes());
            hasher.update(v.version.to_le_bytes());
            match &v.value {
                ObjectValue::Task(t) => {
                    hasher.update(b"task");
                    hasher.update(t.creator.as_bytes());
                    hasher.update(t.bounty.to_le_bytes());
                    hasher.update((t.status as u8).to_le_bytes());
                }
            }
        }
        hasher.finalize().into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use trnm_types::TaskStatus;

    #[test]
    fn put_and_version_update() {
        let mut st = StateStore::new();
        let t = TaskObject {
            task_id: 7,
            creator: "alice".into(),
            bounty: 10,
            status: TaskStatus::Open,
            worker: None,
            committed_hash: None,
            result_hash: None,
            reveal_salt: None,
            version: 1,
        };
        let r1 = st.put_task_new(t.clone()).unwrap();
        assert_eq!(r1.version, 1);

        let mut t2 = t;
        t2.status = TaskStatus::Assigned;
        let r2 = st.update_task(r1, t2).unwrap();
        assert_eq!(r2.version, 2);
    }

    #[test]
    fn version_conflict() {
        let mut st = StateStore::new();
        let t = TaskObject {
            task_id: 1,
            creator: "alice".into(),
            bounty: 1,
            status: TaskStatus::Open,
            worker: None,
            committed_hash: None,
            result_hash: None,
            reveal_salt: None,
            version: 1,
        };
        let r1 = st.put_task_new(t.clone()).unwrap();
        let _ = st.update_task(r1.clone(), t.clone()).unwrap();
        let err = st.update_task(r1, t).unwrap_err();
        assert!(err.contains("version conflict"));
    }
}
