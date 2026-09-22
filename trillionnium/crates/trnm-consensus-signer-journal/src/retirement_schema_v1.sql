CREATE TABLE signer_retirement_v1 (
 singleton INTEGER PRIMARY KEY CHECK(singleton=1),
 record BLOB NOT NULL CHECK(length(record)=354)
) STRICT;
CREATE TRIGGER retirement_no_update_v1 BEFORE UPDATE ON signer_retirement_v1
 BEGIN SELECT RAISE(ABORT,'signer retirement is immutable'); END;
CREATE TRIGGER retirement_no_delete_v1 BEFORE DELETE ON signer_retirement_v1
 BEGIN SELECT RAISE(ABORT,'signer retirement is permanent'); END;
CREATE TRIGGER retired_signer_no_intent_v1 BEFORE INSERT ON sign_intents_v0
 BEGIN SELECT RAISE(ABORT,'ordinary signer is retired'); END;
CREATE TRIGGER retired_signer_no_event_v1 BEFORE INSERT ON signer_journal_events_v0
 BEGIN SELECT RAISE(ABORT,'ordinary signer is retired'); END;
CREATE TRIGGER retired_signer_no_head_v1 BEFORE UPDATE ON signer_journal_head_v0
 BEGIN SELECT RAISE(ABORT,'ordinary signer is retired'); END;
CREATE TRIGGER retired_signer_no_accounting_v1 BEFORE UPDATE ON signer_journal_accounting_v0
 BEGIN SELECT RAISE(ABORT,'ordinary signer is retired'); END;
