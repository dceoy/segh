def feature_fields($names):
  (.security_and_analysis // {}) as $settings
  | [$names[] as $name | {name: $name, status: ($settings[$name].status // null)}];

def observed_status($fields; $id):
  if any($fields[]; .status == "enabled") then "enabled"
  elif $id == "code-security" and any($fields[];
      .status == "disabled" and .name == "code_security") then "disabled"
  elif $id == "secret-protection" and any($fields[];
      .status == "disabled" and .name == "secret_scanning") then "disabled"
  else "unknown"
  end;

def billing_exposure($visibility; $status):
  if $visibility == "public" then "no-additional-license-for-public"
  elif $status == "enabled" then "potential-license-required"
  elif $status == "disabled" then "not-enabled"
  else "unknown"
  end;

def feature($id; $license; $names; $visibility):
  feature_fields($names) as $fields
  | observed_status($fields; $id) as $status
  | {
      id: $id,
      license: $license,
      observed_status: $status,
      billing_exposure: billing_exposure($visibility; $status),
      evidence: $fields
    };

. as $repo
| {
    schema_version: 1,
    repository: $repo.full_name,
    visibility: $repo.visibility,
    source: "repository-metadata.json",
    features: [
      ($repo | feature("code-security"; "GitHub Code Security";
        ["code_security", "advanced_security"]; $repo.visibility)),
      ($repo | feature("secret-protection"; "GitHub Secret Protection";
        ["secret_scanning", "secret_scanning_push_protection", "advanced_security"]; $repo.visibility))
    ],
    limitations: [
      "Settings omitted by the API, including those hidden by permissions, are unknown, not disabled.",
      "This reports potential license exposure, not actual billed seats, license grants, or invoices.",
      "Code scanning uploads in workflows and organization-level policy are not determined by this metadata."
    ]
  }
