# approval-webhook — delta for close-audit-and-loader-gaps

## MODIFIED Requirements

### Requirement: Guarantee wire conformance with the upstream crate

The test suite SHALL verify the wire types against nono's own types by serializing upstream request values and asserting both that they deserialize into the service's mirrors and that their exact key set is unchanged. The `nono` crate SHALL be a development dependency only.

The command-request corpus SHALL model every `intercept_rule` shape the upstream tool sandbox actually produces, verified against upstream's rule-label construction rather than assumed: the matched intercept rule's arguments joined with spaces (single token `status`, multi-token `push --force`), the `<catch-all>` label of an empty-args rule, and the invocation-policy label forms `invocation_policy.approve[<index>]` and `invocation_policy.default`. A corpus that models only the single-token shape SHALL be treated as a defect, because it cannot catch a policy or audit consumer that assumes one word.

#### Scenario: Upstream key set change fails the build

- **WHEN** a nono version bump changes the field set of a `command` or `endpoint` approval request
- **THEN** the conformance test fails, rather than the daemon silently misreading a security decision

#### Scenario: Filesystem capability requests are classified unsupported

- **WHEN** a `capability` approval request produced by upstream's own types is parsed
- **THEN** it is classified as unsupported, which resolves to a denial

#### Scenario: The fixture corpus models the real intercept_rule shapes

- **WHEN** the command-request test corpus is enumerated
- **THEN** it contains payloads whose `intercept_rule` is a single token, a space-joined multi-token rule, the `<catch-all>` label, and an `invocation_policy.*` label — each driven through parse, evaluation and audit with the value surviving to the audit line byte-identically (none of the real shapes contains a control character; hostile control bytes are escaped at the audit boundary like every other request-derived field)
