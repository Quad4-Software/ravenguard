# Machine learning score

RavenGuard ships a pure-Go linear model that scores structured features (headers, JA4 presence, behavior, Coraza hits, semantic family scores). Enforce modes require a passing eval attestation.

## Config

```toml
[ml]
enabled = false
mode = "shadow"
model_path = "assets/ml/base.bin"
adapt_path = "assets/ml/adapt.bin"
challenge_prob = 0.75
block_prob = 0.95
confidence_min = 0.85
fpr_gate = 0.001
shadow_sample_rate = 0.02
max_points = 60
```

Modes: off, shadow, challenge, block.

challenge and block stay forced to shadow until assets/ml/base.bin.attest.json passes for the loaded model hash.

## Prove FP rate

```bash
go run ./cmd/rg-ml-eval/ -root testdata/ml -model assets/ml/base.bin -attest assets/ml/base.bin.attest.json
```

The harness fails if benign FPR exceeds fpr_gate or attack TPR is below the floor.

## Local adaptation

Shadow samples land in ml_samples. Operators label FP/TP in the admin Requests page, then run adapt. The overlay swaps atomically and never blocks the request path. Adapt rolls back if FPR rises after re-eval.

## Performance

Inference is in-process with pooled feature scratch. No ONNX or CGO on the request path. Clean-path budgets are enforced in benches under internal/ml and internal/semantic.
