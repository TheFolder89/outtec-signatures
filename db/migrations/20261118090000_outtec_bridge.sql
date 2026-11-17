-- Each integration request has its own non-interactive owner. There is no
-- organization-wide sender session and no access through a user-supplied URL.
CREATE TABLE outtec_bridge_requests (
  request_id uuid PRIMARY KEY,
  owner_id text NOT NULL REFERENCES public."user"(id),
  envelope_id text UNIQUE REFERENCES envelopes(id),
  source_hash text NOT NULL CHECK (source_hash ~ '^[a-f0-9]{64}$'),
  signature_method text NOT NULL CHECK (signature_method IN ('SIMPLE', 'ICP_BRASIL')),
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE outtec_bridge_operations (
  id uuid PRIMARY KEY,
  request_id uuid NOT NULL,
  input_hash text NOT NULL,
  result jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE outtec_bridge_nonces (
  nonce uuid PRIMARY KEY,
  created_at timestamptz NOT NULL DEFAULT now()
);
