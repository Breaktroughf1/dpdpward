-- Fictional lending app schema (demo only; contains no real data).
CREATE TABLE customers (
  id            BIGSERIAL PRIMARY KEY,
  full_name     VARCHAR(200) NOT NULL,
  email         TEXT UNIQUE NOT NULL,
  email_verified BOOLEAN DEFAULT false,
  mobile_number VARCHAR(15),
  aadhaar_number CHAR(12),
  pan           CHAR(10),
  date_of_birth DATE,
  address_line1 TEXT,
  pincode       CHAR(6),
  created_at    TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE loans (
  id                  BIGSERIAL PRIMARY KEY,
  customer_id         BIGINT REFERENCES customers(id),
  amount              NUMERIC(12,2) NOT NULL,
  bank_account_number VARCHAR(20),
  ifsc                CHAR(11),
  upi_id              VARCHAR(100),
  monthly_income      NUMERIC(12,2)
);

CREATE TABLE audit_log (
  id          BIGSERIAL PRIMARY KEY,
  actor_email TEXT,
  ip_address  INET,
  action      TEXT,
  created_at  TIMESTAMPTZ DEFAULT now()
);
