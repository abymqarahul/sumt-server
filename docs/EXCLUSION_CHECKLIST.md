# Exclusion checklist (release gate)

None of these may appear in navigation, the dashboard, search, settings, the feature registry, admin config, strings, or the backend `ResourceKind`/feature flags.

| # | Excluded | Grep patterns (case-insensitive) that must return 0 hits in `customer-app/` and `admin-app/` |
|---|---|---|
| 1 | Resistor Tools | `resistor` |
| 2 | Screen TEST | `screen ?test`, `ScreenTest`, `display test` |
| 3 | DTH Logo Changer | `dth`, `logo ?changer` |
| 4 | Hex Editor | `hex ?editor`, `HexBuffer`, `hexedit` |
| 5 | UART Connection Detail (standalone) | `UartConnectionDetail`, `connection detail` |
| 6 | YouTube Channel | `youtube` |
| 7 | About | `About_us`, `AboutActivity`, `"About"` |
| 8 | Terms | `TermsActivity`, `"Terms"` |
| 9 | Original Pro Workspace | `workspace` (in feature registry) |

Branding gate: `gkc` and `gkc terminal` must return 0 hits in both apps and in the backend (including resource file names).

Allowed: internal UART transport classes (`UartTransport`, `SerialSession`) used by the recovery tools.

Automated: `scripts/release-audit.sh` (added with the Android phase) runs these greps and fails the build when any pattern matches.
