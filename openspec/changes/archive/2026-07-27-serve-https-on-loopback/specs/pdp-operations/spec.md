# pdp-operations — delta for serve-https-on-loopback

## ADDED Requirements

### Requirement: Serve https on loopback with a locally-trusted certificate

The service SHALL support serving its HTTP surface over TLS on the configured loopback
address, so that a process which cannot read the private key cannot answer nono's approval
requests in the daemon's place. nono's webhook client verifies with the **platform** trust
store, so a certificate trusted there is what makes a squatter's handshake fail; a failed
handshake blocks the intercepted command, which is the fail-closed outcome.

TLS SHALL be opt-in. With no TLS configuration the service SHALL serve plaintext exactly as
before and SHALL emit a warning naming PDP impersonation, so the operating posture appears
in the log rather than being inferred from the absence of one.

When TLS is configured the service SHALL refuse to serve rather than fall back to plaintext
on any failure to establish it — an unreadable, unparseable or mismatched certificate and
key, a key that fails the readability rule below, or a certificate the platform verifier
does not accept. A silent downgrade SHALL NOT occur under any condition: an operator who
believes the transport is authenticated when it is not is worse off than one who never
configured it, because the belief is what the deployment is built on.

The private key SHALL be refused when it is readable by other local users — group- or
world-readable, owned by neither the daemon's effective uid nor root, or reachable through
an ancestor those rules reject. This SHALL be a refusal rather than a warning: unlike the
working-directory heuristic, it is not a proxy for the invariant but a direct measurement of
it, with no false-positive case that would breed an override flag. The service SHALL NOT
represent this check as defending against the sandboxed agent — the agent runs as the same
uid, so what separates it from the key is the key's location relative to the profile's read
grants, not the key's mode.

Before binding its listener, the service SHALL verify its own certificate through the same
platform verifier its client uses, for the server name implied by the configured bind
address, and SHALL refuse to serve when that verification fails. The verification SHALL
complete before the listener accepts any connection, so that there is no interval in which
the service answers approvals it has not established anyone can trust.

The service SHALL document that the URL configured in a nono profile names the literal
address the daemon binds, not a hostname that resolves to it. `localhost` resolves to the
IPv6 loopback before the IPv4 loopback on macOS, so a daemon on `127.0.0.1` and a squatter
on `::1` can both start cleanly while every `localhost` request reaches the squatter;
selecting the listener by resolver order is not an acceptable property of the artifact whose
purpose is knowing who answered.

The service SHALL NOT report its transport on the health endpoint. A client that completed a
handshake already knows, and one that did not cannot read the response.

#### Scenario: No TLS configuration serves plaintext and says so

- **WHEN** the configuration declares no TLS certificate and key
- **THEN** the daemon serves plaintext on the configured loopback address and logs a warning naming PDP impersonation

#### Scenario: A half-configured transport fails the load

- **WHEN** the configuration declares a certificate without a key, or a key without a certificate
- **THEN** loading fails with an error naming the missing key, and the daemon does not bind

#### Scenario: An unusable certificate or key refuses to serve

- **WHEN** TLS is configured but the certificate or key is unreadable, unparseable, or the two do not match
- **THEN** the daemon reports the failure and exits non-zero without binding a port, and does not serve plaintext instead

#### Scenario: A private key readable by other local users refuses to serve

- **WHEN** the configured private key is group- or world-readable
- **THEN** the daemon reports the failure and exits non-zero without binding a port

#### Scenario: An untrusted certificate refuses to serve before accepting anything

- **WHEN** TLS is configured with a certificate the platform verifier does not accept for the bind address
- **THEN** the daemon reports the failure and exits non-zero, and no connection is ever accepted on the configured address

#### Scenario: A trusted certificate serves decisions unchanged

- **WHEN** TLS is configured with a certificate the platform verifier accepts
- **THEN** the daemon answers `POST /v1/approve` and `GET /healthz` over https on the configured loopback address, with the same decisions it would have returned over plaintext

#### Scenario: A squatter without the key cannot be believed

- **WHEN** a process holding the configured port presents a certificate whose key it does not control, and nono requests an approval
- **THEN** the TLS handshake fails, nono treats it as a transport failure, and the intercepted command is blocked rather than allowed

## MODIFIED Requirements

### Requirement: Strict operator configuration

The service SHALL read a TOML configuration file declaring the bind address, policy directory, audit log path, the approval-backend-name to Cedar `Agent` map, and optionally a TLS certificate and private key. Unknown configuration keys SHALL be a load error, because a silently ignored typo in a security daemon's configuration is worse than a failed start. The unknown-agent fallback identity SHALL NOT be configurable: the shipped baseline policy denies `Nono::Agent::"unknown"` by that exact name, and a knob that renames the fallback silently disables the deny. A leading `~/` in a path SHALL be expanded to the user's home directory.

The TLS certificate and key SHALL be required together. A configuration declaring one without the other SHALL be a load error rather than a partial application, because a half-configured transport is a misconfiguration the operator must see, not a state the daemon can resolve on their behalf.

#### Scenario: Minimal configuration applies documented defaults

- **WHEN** the configuration declares only `policy_dir`
- **THEN** the bind address defaults to `127.0.0.1:8181`, the agent map is empty, and no TLS is configured

#### Scenario: Misspelled key fails the load

- **WHEN** the configuration contains a key the schema does not define
- **THEN** loading fails with a parse error naming the problem

#### Scenario: A misspelled key inside the TLS table fails the load

- **WHEN** the TLS table contains a key the schema does not define
- **THEN** loading fails with a parse error naming the problem, so the strictness rule reaches the nested table too

#### Scenario: A configuration carrying the removed unknown_agent key fails loudly

- **WHEN** a configuration sets `unknown_agent`, the key that once renamed the fallback identity
- **THEN** loading fails with a parse error naming `unknown_agent`, so the operator learns the knob is gone rather than having the setting silently ignored

#### Scenario: Home-relative paths are expanded

- **WHEN** a path is written as `~/policies`
- **THEN** the resolved path is absolute and contains no `~`

#### Scenario: Home-relative TLS paths are expanded

- **WHEN** the TLS certificate or key is written as `~/.config/nono-cedar-pdp/tls/cert.pem`
- **THEN** the resolved path is absolute and contains no `~`
