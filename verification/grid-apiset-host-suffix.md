# API-set driver host names

The follow-up to the version 6 discovery packet permits `.sys` host basenames in
API-set namespace values. Windows diagnostic run `42984039287` captured the exact
144800-byte schema with SHA256
`fd45c0d71100c8d2bff924fc7650b1c2c869fbeea6f8d1f521315e6781de4aaa`.
It retained 32 rejections across five driver names; ten additional rejected values
were omitted by the diagnostic budget. The first retained host was `win32kbase.sys`.

Only API-set host suffix validation changes. DLL-only aliases, ordinary and delayed
PE import validation (including its existing named `winspool.drv` exception), name
character restrictions, schema bounds and count/length limits retain their rules.
Parsing captures names as data; it does not load a DLL or driver.

`node --test platform/grid-host-discovery-v5/apiset-schema.test.mjs` runs bounded,
in-memory synthetic regressions using the emitted contract/host strings. The original
Windows PE was not retained, and the tests do not recreate the complete schema or
the ten omitted values. This source change requires a fresh original Windows
discovery run before claiming that the captured schema now passes in the real flow.

The discovery `FREEZE.json`, `CODE-CLOSURE.json` and `ORACLE.json` identities are
updated for the changed parser and added tests. Historical preparation evidence stays
historical; the original workspace verification commands are not portable checkout
commands. Host, source, build, runtime and artifact selection remain separate steps.
