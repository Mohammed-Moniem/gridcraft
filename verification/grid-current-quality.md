# Current Grid source and CLI verification

Full required matching-Rust1.95 CI passed all10 stages: 3,589 passing cases, zero failures and one existing ignored timing test. The165 focused I/O, policy, host, dialog/window and CLI identities are subsets of that total. Doctests ran zero cases. WASM checks12 packages including gridcraft-web; this is compilation, not browser runtime acceptance. CI used a reused cache, offline vendors and an admitted local-server environment: wildcard and IPv6 binds are allowed; one external TCP probe is OS-denied. No global isolation/airgap proof is claimed. Earlier environmental failures remain preserved.

Source freeze: `f6c260d0731acc240aff399fa302ab770f5d8e63df754d6b101fa75fdb8b1db9`; fresh critic manifest: `5d414b19156b7a95c9f8ea155fd404ca7da410347ca4714daca14e9442ac8957`. Parent source replay bd8c42 passed all4gates after native return; independent critic replay419853 passed bothgates. These are bounded source decisions.

- `crates/engine/src/io.rs`: `2ebe42d92987863b81c250a98686ec7297cdd90d0d815c38a22299426cda2ea4`
- `crates/engine/src/io/tests.rs`: `224567958f29e60e42b8b48d7a739f8ad4dea1f04d38f2655fb7b313e6c2985f`
- `crates/ui-egui/src/dialogs/show.rs`: `33756153dc96bfad553304cc11e443b5a8dff23da6568071dfb6df433f2a4877`
- `crates/ui-egui/src/hosted.rs`: `76fa504473b72cc1e68429f2166d922effba8b18c6e7cf76413e901d58b42686`
- `apps/gridcraft-cli/src/main.rs`: `69a037008f391d712386c39a0e96d3845c5667310ce907a4eb550a2e8f73185c`

Native CLI:21,135,280 bytes, SHA256 `24fb132d7659afe0c0b38c5feffd6b3f191da14a3e0af75ee66076913e013dcf`, built with frozen/offline Rust1.95, reused target cache and actual original-policy EPERM. No clean-target proof. The native archive has separate real extracted-workflow evidence; general races, writer liveness, fsync/power-loss, ACL/UID/GID preservation, other targets, UI/private-host and Office parity remain outside this proof. Captured legal files are a reference superset, not a linked-crate SBOM. No new contributor identity or CI change is included.
