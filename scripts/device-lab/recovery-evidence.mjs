// Read-only server assertions for the dedicated iOS missing-key flow.
import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
const [phase, databasePath, evidencePath, subject] = process.argv.slice(2);
assert(["before", "failed-restore", "recovered"].includes(phase));
assert(
  databasePath && evidencePath && subject,
  "Supply phase, fixture DB, evidence file and subject",
);
const db = new DatabaseSync(resolve(databasePath), { readOnly: true });
const user = db.prepare("select email from user where id=?").get(subject);
assert(
  user?.email.endsWith("@example.test"),
  "Use a dedicated example test account",
);
const snapshot = {
  credentials: db
    .prepare(
      "select id, providerCredentialId, dpopJkt, status from firstPartyCredential where userId=? order by id",
    )
    .all(subject),
  families: db
    .prepare(
      "select id, credentialId, dpopJkt, status from firstPartyTokenFamily where userId=? order by id",
    )
    .all(subject),
  refresh: db
    .prepare(
      "select r.id,r.familyId,r.status from firstPartyRefresh r join firstPartyTokenFamily f on f.id=r.familyId where f.userId=? order by r.id",
    )
    .all(subject),
};
db.close();
// SQLite rows have null prototypes; compare their persisted JSON values.
const current = JSON.parse(JSON.stringify(snapshot));
const evidence =
  phase === "before" ? {} : JSON.parse(readFileSync(evidencePath, "utf8"));
if (phase === "before") {
  assert.equal(current.credentials.length, 1, "Use a fresh account fixture");
  assert.equal(current.families.length, 1);
  assert.equal(current.refresh.length, 1);
} else if (phase === "failed-restore") {
  assert.deepEqual(
    current,
    evidence.before,
    "Failed restore must neither replace identity nor refresh server authority",
  );
} else {
  assert.equal(current.credentials.length, 2);
  assert.equal(current.families.length, 2);
  const old = evidence.before.credentials[0];
  assert.deepEqual(
    current.credentials.find((c) => c.id === old.id),
    old,
  );
  const replacement = current.credentials.find((c) => c.id !== old.id);
  assert.notEqual(replacement.dpopJkt, old.dpopJkt);
  assert.notEqual(replacement.providerCredentialId, old.providerCredentialId);
  assert.equal(replacement.status, "active");
  assert.deepEqual(
    current.families.find((f) => f.id === evidence.before.families[0].id),
    evidence.before.families[0],
  );
}
evidence[phase] = current;
evidence.recordedAt = new Date().toISOString();
writeFileSync(evidencePath, JSON.stringify(evidence, null, 2) + "\n", {
  mode: 0o600,
});
console.log(`Server recovery evidence passed: ${phase}`);
