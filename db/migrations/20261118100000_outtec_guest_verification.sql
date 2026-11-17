CREATE TABLE outtec_bridge_guest_codes (
  request_id uuid NOT NULL REFERENCES outtec_bridge_requests(request_id),
  email text NOT NULL,
  code_hash text,
  expires_at timestamptz NOT NULL,
  attempts integer NOT NULL DEFAULT 0,
  last_sent_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (request_id,email)
);
