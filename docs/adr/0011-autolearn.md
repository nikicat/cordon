# ADR 0011: Autolearn

Status: Accepted, not implemented ([todo.md](../../todo.md))

## Context

Writing an allow rule for every tool by hand is the prompt fatigue that killed earlier
per-app file gates (see [prior art](../prior-art.md)). Trust-on-first-use claimed paths on
create, and it was retired with the owner model.

## Decision

Autolearn generalizes trust-on-first-use into a bounded training mode, in the lineage of
AppArmor's complain
mode and fapolicyd's trust database. `zones` are the scope where autolearn may propose rules.
- Activation is explicit (`cordon learn`), and the window is bounded. The trust window is the
  whole vulnerability, because anything malicious that runs during learning gets trusted. So
  learned rules are never enforced automatically, and they are reviewed before promotion.
- Generalize by collapsing per-file opens into a subtree rule. Track confidence by how many
  times a pattern was seen, and deduplicate. Otherwise you drown in candidates.
- Record the *rich* subject (argv0, ancestor, hash), so that promoted rules are tight rather
  than just `exe=python3`.
- `cordon learn review` shows a diff of the proposed rules and promotes them into the text
  file. The learned database is throwaway, and the text file is durable.

## Consequences

Learned rules live in their own database, have lower precedence, and never override a
hand-written deny ([ADR 0010](0010-policy-storage.md)).
