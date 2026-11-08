# Reviewed Grid host-discovery preparation

This personal repository carries the selected preparation code in `platform/grid-current-v5` and `platform/grid-host-discovery-v5`. Their self-excluding freezes list 85 and 26 members; both FREEZE files are also included. No selected packet byte was rewritten for publication.

Verify the two FREEZE files with a trusted SHA256 tool, then compare every listed path, byte count, mode and SHA256 with the checked-out files:

- Platform FREEZE: `c1b7ffc41e97b3be6fba897a372829c85f7fa05631da112c3df2cd40186a3eb3`
- Discovery FREEZE: `64c3712def500d62860c08f6372cbe6b65c8b12935bbc9ea161c334c256265a5`

The packet's historical metadata preserves review provenance. Its `prepare-metadata.mjs` and preparation-review `verify.mjs` depend on the original audit workspace; they are not standalone public-checkout commands. Publication does not copy those referenced audit captures or run a candidate helper. The fixed discovery entrypoint uses the paired frozen packet bytes and a separately selected external envelope.

The new active workflow is manual `workflow_dispatch` only. It has the fixed personal-repository guard, pinned checkout/upload actions and ARM64 macOS, real Intel macOS and Windows Server 2022 targets. Before dispatch, independently review the exact published code head and an externally supplied envelope binding that head, both freezes, all target launch documents and their review/replay identities. No launch envelope is included or issued by this publication. A later per-target `PREPARATION_CODE_ONLY` admission must separately bind actual consuming-host observations and selected stages before builds.

Built products still derive from the preserved source commit `17c5aba04c33b107ec3a9264b0fa6f28966faf2c`, tree `c4544e89868075cca2570ede803540bdbf0afae9`, source archive SHA256 `01b4d9d365d7265a26e0446a81f256e0c56094769a6f641a03ce7867bd47de27`. Publishing preparation changes the repository workflow/code head and does not rebuild that archive or replace the existing source/macOS ARM64 progress release.

The selected preparation review includes 19 owned-filesystem policy cases and inherited byte-identical 34-case local archive-parser evidence. These are bounded evidence scopes. Actual discovery, target builds, native/GUI/browser qualification, Windows 11, private-host integration, Microsoft Office parity and full-goal acceptance remain pending.

The preparation helpers retain their [MIT integration licence](../platform/grid-current-v5/LICENSE-SUITE-TOOLS). Grid's existing MIT/Apache licences, notices, attribution, contributor data, original README and source provenance remain unchanged. No new dependency or asset is added.
