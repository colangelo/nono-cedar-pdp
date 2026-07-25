# cedar-policy-evaluation — delta for close-audit-and-loader-gaps

## MODIFIED Requirements

### Requirement: Load policies with traceable identifiers

The service SHALL load every `*.cedar` file in the configured policy directory and assign each policy an identifier of the form `<file stem>:<id annotation or ordinal>`, so a decision names the file and rule that produced it. Duplicate identifiers SHALL be a load failure, never a silent overwrite. Files without the `.cedar` extension SHALL be ignored.

Two shapes of `*.cedar` path SHALL be skipped rather than failing the load: a name starting with `.` or `#` (what editors give lock files and backups, which would otherwise abort every reload for the duration of an editing session), and anything that is not a regular file (a directory, a socket, a symlink with no target). Each skip SHALL be logged at WARN naming the path and the reason, because a skipped file is a policy the operator wrote that decides nothing — a silently ignored `.baseline.cedar` is a hole in the policy set with no trace.

A directory entry the listing itself fails to yield — an entry whose name or metadata cannot be read — SHALL fail the load with an error naming the directory, never be silently dropped: the service cannot classify what it could not read, so it cannot know the entry was not a policy, and an unreadable entry in a policy directory is the shape of a tampering symptom. (At reload, the existing last-known-good requirement applies: the previous set is retained and the failure is logged.)

#### Scenario: Policy identifiers carry file provenance

- **WHEN** `10-git.cedar` contains a policy annotated `@id("no-history-rewrites")` and one without an annotation
- **THEN** the loaded identifiers are `10-git:no-history-rewrites` and `10-git:<ordinal>`

#### Scenario: Duplicate identifiers fail the load

- **WHEN** two policies resolve to the same identifier
- **THEN** loading fails with an error naming the file

#### Scenario: Non-policy files are ignored

- **WHEN** the policy directory also contains a `README.md`
- **THEN** it is not loaded and does not affect validation

#### Scenario: A skipped policy file is named in the log

- **WHEN** the policy directory contains `.baseline.cedar`, an editor lock file `.#10-git.cedar`, or a directory named `archive.cedar`
- **THEN** the load succeeds without them and each skip is logged at WARN naming the path and why it is not in force

#### Scenario: An unreadable directory entry fails the load

- **WHEN** enumerating the policy directory yields an entry that cannot be read
- **THEN** the load fails with an error naming the directory, rather than continuing without the entry as though it did not exist

### Requirement: Deny endpoint requests whose path is ambiguous

nono's proxy sends the raw upstream path: not normalised and still percent-encoded. A
prefix glob such as `resource.path like "/repos/*"` is therefore satisfied by
`/repos/../user/keys`, `/repos/%2e%2e/user/keys` and `/repos/..;/user/keys`, which a
normalising origin resolves elsewhere. The service SHALL NOT normalise the path (that
would both change what a policy matches and guess at the upstream's behaviour); instead
it SHALL deny an endpoint request whose path's meaning depends on normalisation rules,
**before any policy is consulted**, with a deny reason naming the ambiguity and the path
as sent. Unambiguous paths SHALL continue to be evaluated with the raw path value.

The guard SHALL NOT be bypassable through the library's public surface: the pieces
that build an authorization request from a policy query and the pieces that convert a
raw authorizer response into a decision SHALL NOT be publicly exported, so the only
externally reachable route from a policy query to a decision runs the ambiguity check
first. This is the same closed-seam property the engine's constructors already have.

The examined part of the target SHALL be everything before the first raw `?`, and no
other truncation SHALL be applied. RFC 3986 §5.2.4 defines `remove_dot_segments` over the
path component alone, so excluding the query is a specified boundary rather than an
assumption about the upstream. In particular a raw `#` SHALL NOT end the scan: an
origin-form request target carries no fragment (RFC 9112 §3.2.1), so whether an upstream
treats a raw `#` as a delimiter is exactly the kind of upstream-dependent meaning this
requirement refuses to guess at.

A path SHALL be treated as ambiguous when, over that part of the target:

1. a segment is `.` or `..` after stripping `;`-parameters — where segments are separated
   by `/` **or `\`**, the WHATWG URL standard folding a backslash onto a forward slash for
   http(s) — at **any** percent-decode
   depth up to a bound the service SHALL declare — not merely the first, because the
   service cannot know how many decode hops sit between it and the origin, so
   `%252e%252e` is refused for the same reason as `%2e%2e`;
2. the path **as sent** contains a malformed percent-escape (a `%` not followed by two
   hex digits), or decodes to bytes that are not UTF-8 — an overlong encoding such as
   `%c0%ae` is a `.` to some servers; or
3. its percent-encoding nests deeper than the declared bound, so the traversal check
   above could not be completed.

Ambiguity SHALL NOT be inferred from the query string (a `..` in a query value cannot
change which resource the origin routes to, and `?path=../x` is an ordinary API
parameter), from dots inside a segment (`/repos/foo..bar`), from a `#` or `\` that is not
part of a `.`/`..` segment (`/issues/issue#5`, `/repos/foo\bar`), or from an undecodable
escape that appears only *after* the first decode pass — `/x/50%25-done` legitimately
decodes to `50%-done`, whose stray `%` is data.

#### Scenario: A traversal after a raw `#` is denied

- **WHEN** an endpoint request's path is `/repos/foo#/../../user/keys`
- **THEN** the decision is deny, because the scan does not stop at the `#` — treating it as a fragment delimiter would let everything after it escape inspection while an upstream that does not treat it as one still resolves the traversal

#### Scenario: A traversal built from backslash separators is denied

- **WHEN** an endpoint request's path is `/repos/..%5C../user/keys` or `/repos/\..\user/keys`
- **THEN** the decision is deny, because `\` separates segments wherever `/` does

#### Scenario: A traversal inside the query string is not denied

- **WHEN** an endpoint request's path is `/search?q=..%2F..%2Fetc`
- **THEN** the query part triggers no ambiguity refusal and the request is decided by policy on the raw path

#### Scenario: A literal traversal segment is denied without policy evaluation

- **WHEN** an endpoint request's path contains a literal `..` segment, such as `/repos/../user/keys`
- **THEN** the decision is deny, the reason names the ambiguity and the path, and no policy is credited with the decision

#### Scenario: A percent-encoded or parameterised traversal segment is denied

- **WHEN** an endpoint request's path encodes a traversal segment at any decode depth within the declared bound (`/repos/%2e%2e/user/keys`, `/repos/%252e%252e/user/keys`) or hides it behind `;`-parameters (`/repos/..;/user/keys`)
- **THEN** the decision is deny with the ambiguity named in the reason

#### Scenario: An undecodable path is denied rather than guessed at

- **WHEN** an endpoint request's path contains a malformed percent-escape as sent (`/repos/%zz/foo`) or decodes to non-UTF-8 bytes (`/repos/%c0%ae/foo`)
- **THEN** the decision is deny, because the service cannot know what the upstream will resolve without guessing

#### Scenario: An unambiguous path is still decided by policy

- **WHEN** an endpoint request's path is `/repos/foo/bar` and a permit matches `resource.path like "/repos/*"`
- **THEN** the decision is allow, with the raw path value visible to the policy

#### Scenario: The ambiguity refusal is reproducible offline

- **WHEN** an operator replays a denied ambiguous-path request through the offline check command
- **THEN** the same deny and reason are produced, because the check runs inside evaluation rather than in the HTTP layer

#### Scenario: The bypass pieces are not exported

- **WHEN** the library's public surface is inspected from outside the crate
- **THEN** no public item builds a Cedar authorization request from a policy query or converts a raw authorizer response into a decision, and a visibility tripwire fails the suite if either is re-exported
