# ShockWave DVGA Benchmark Dataset

This benchmark evaluates `ShockWave` (`shockwave`) against Damn Vulnerable GraphQL Application (DVGA) target.

## Setup Instructions

1. Run the DVGA docker container:
   ```bash
   docker run -d -p 5013:5013 dolevf/dvga
   ```
2. Retrieve candidate user tokens from database seeding details or register two accounts:
   - Account A (Lower privileges) -> Auth token A
   - Account B (Higher privileges) -> Auth token B

3. Run the benchmark tool:
   ```bash
   shockwave benchmark
   ```
