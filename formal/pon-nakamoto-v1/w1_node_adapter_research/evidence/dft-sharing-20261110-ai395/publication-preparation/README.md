# Preserved publication preparation refusal

The first ai395 evidence commit failed with exit128 because the dedicated
checkout had no configured author identity. It did not create a commit or
perform a GitHub write. The exact stderr is [retained](delivery-commit.stderr).
The recovery uses the existing source commit's recorded author name/email
as command-local Git overrides; no global/shared Git configuration is changed.
This author metadata is not proof of an authenticated GitHub actor. Actual
GitHub publication still requires the Mac-local ProfHepta channel and preflight.
