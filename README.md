#Synthetic Edge Case Fraud Data Generator
A sophisticated system for generating realistic, diverse, and novel synthetic fraud data for testing and validation purposes. This generator produces edge cases that stress-test fraud detection systems while maintaining privacy and avoiding the creation of actual attack blueprints.

#Overview
The Synthetic Edge Case Fraud Data Generator creates high-quality synthetic fraud data that matches real-world characteristics while introducing controlled novelty and diversity. It's designed to help organizations test their fraud detection systems against rare and emerging attack patterns without exposing sensitive information or enabling malicious use.

#System Architecture

1. Data Contract & Taxonomy Layer
Schema Contracts: Enforces types, ranges, cross-field constraints, temporal ordering, and graph invariants
Fraud Taxonomy: Covers account opening fraud, account takeover (ATO), card-not-present (CNP), refund abuse, promo abuse, mule rings, and more
Configurable Parameters: Velocity profiles, device churn patterns, ASN reputation bands, ring sizes, inter-event timing

2. Hybrid Generation Engine
Mechanistic Simulators: Rule-based and agent-based models for causal structure and constraints
Learned Models: Context-conditioned neural networks for realism and correlations
- Tabular: CTGAN/TVAE/tabular diffusion, copula models
- Sequential: Transformer-based diffusion, TimeGAN for sessions/transactions over time
- Graph: GraphRNN/GRAN/VAEs for device↔user↔payment networks with degree & motif constraints

Counterfactual Engine: Applies minimal, plausible edits to benign sequences to create edge cases

3. Constraint & Privacy Validator
Hard Constraints: Enforces sums, chronology, checksum formats
Soft Penalties: Maintains feature marginals for realism
Privacy Protection: Strips/randomizes identifying patterns, tests for membership inference
Realness Model: Discriminator-style validation without creating detector feedback loops

4. Scenario Orchestrator
Constrained Decoding: Uses rejection sampling until all quality tests pass
Difficulty Tiers:
- T1: Plausible scenarios
- T2: Evasive patterns
- T3: Adversarial examples

Cost Tagging: Provides intended friction costs for client selection

5. Drift & Novelty Engine
Covariate Shift Monitoring: PSI/CMMD tracking on privacy-scrubbed marginals for monthly retuning
Threat Intelligence Integration: Incorporates analyst feedback and high-level patterns (no attack details)
Novelty Search: Evolutionary strategies to explore unseen but plausible scenarios
