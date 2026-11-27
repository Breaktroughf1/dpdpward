# FAQ

**Is this legal advice? Does a clean report mean we comply with DPDP?**
No to both. dpdpward is a technical aid. It shows where personal data sits in code, whether each store has a declared purpose, basis and retention, and what evidence exists for the Rule 6 safeguards. Whether processing is lawful, consent is valid or a notice is adequate is for you and your counsel. See [legal basis and its limits](legal-basis.md).

**Does it read our databases or send data anywhere?**
No. It reads source files and Terraform only, makes no network calls and opens no database connections. Identifier values found in files (Aadhaar, PAN, UPI and others) are always redacted in output.

**Which stacks does it understand?**
SQL DDL, Prisma, Django, SQLAlchemy, Laravel, Rails, TypeORM, Sequelize, Drizzle, Mongoose, JPA/Hibernate, EF Core and Go structs. For infrastructure it reads Terraform.

**We use a privacy platform (OneTrust, Securiti, BigID or an Indian DPDP platform). Why add this?**
Those platforms discover data in running systems and manage consent and requests. dpdpward runs on every pull request, *before* data exists. It catches a new `aadhaar_number` column or an unencrypted bucket at review time, and keeps your data map and ROPA in step with the code. Use its JSON or CSV output to feed the platform.

**Why does a safeguard show PARTIAL when Terraform is correct?**
Configuration is not evidence that a control works. A safeguard is **PASS** only when you attest it in `dpdpward.yaml` and the evidence you cite exists. Terraform alone makes it **PARTIAL**. Undecided is **UNKNOWN**, never met.

**It flagged a field that is not personal data.**
Add it to `ignore` in `dpdpward.yaml` with a reason, and open an issue with the field name so the classifier can improve. An `ignore` entry without a reason is not applied.

**Will it fail CI on day one?**
Not if you approve today's map first: `dpdpward baseline`, then `scan --baseline`. Only new personal data, or new findings, fail the build.

**When do the obligations apply?**
Most duties, including notice, consent, Rule 6 safeguards and Rule 7 breach intimation, apply from 13 May 2027 under the November 2025 commencement notification. Check the current position; see [dates](legal-basis.md#dates).

**Can I try it without our code?**
Yes: `dpdpward demo`, or `dpdpward demo --format html -o dpdpward-demo.html`.
