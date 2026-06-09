INSERT INTO scopes (name, description) VALUES
    ('read', 'Read access to user resources'),
    ('write', 'Write access to user resources'),
    ('openid', 'OpenID Connect authentication'),
    ('profile', 'Access to user profile information');

INSERT INTO clients (
    client_id, client_secret, name, client_type,
    access_token_ttl_seconds, refresh_token_ttl_seconds,
    created_at, updated_at
) VALUES (
    'demo-client',
    '$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy',
    'Demo Confidential Client',
    'CONFIDENTIAL',
    3600,
    1209600,
    CURRENT_TIMESTAMP,
    CURRENT_TIMESTAMP
);

INSERT INTO clients (
    client_id, client_secret, name, client_type,
    access_token_ttl_seconds, refresh_token_ttl_seconds,
    created_at, updated_at
) VALUES (
    'public-client',
    NULL,
    'Demo Public Client',
    'PUBLIC',
    3600,
    1209600,
    CURRENT_TIMESTAMP,
    CURRENT_TIMESTAMP
);

INSERT INTO client_redirect_uris (client_id, redirect_uri)
SELECT id, 'http://localhost:3000/callback' FROM clients WHERE client_id = 'demo-client';

INSERT INTO client_redirect_uris (client_id, redirect_uri)
SELECT id, 'http://localhost:3000/callback' FROM clients WHERE client_id = 'public-client';

INSERT INTO client_grant_types (client_id, grant_type)
SELECT c.id, gt.grant_type
FROM clients c
CROSS JOIN (VALUES ('AUTHORIZATION_CODE'), ('CLIENT_CREDENTIALS'), ('PASSWORD'), ('REFRESH_TOKEN')) AS gt(grant_type)
WHERE c.client_id = 'demo-client';

INSERT INTO client_grant_types (client_id, grant_type)
SELECT c.id, gt.grant_type
FROM clients c
CROSS JOIN (VALUES ('AUTHORIZATION_CODE'), ('REFRESH_TOKEN')) AS gt(grant_type)
WHERE c.client_id = 'public-client';

INSERT INTO client_scopes (client_id, scope_id)
SELECT c.id, s.id
FROM clients c, scopes s
WHERE c.client_id = 'demo-client' AND s.name IN ('read', 'write', 'openid', 'profile');

INSERT INTO client_scopes (client_id, scope_id)
SELECT c.id, s.id
FROM clients c, scopes s
WHERE c.client_id = 'public-client' AND s.name IN ('read', 'openid', 'profile');

INSERT INTO users (username, password_hash, email, enabled, created_at)
VALUES (
    'demo-user',
    '$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy',
    'demo@example.com',
    TRUE,
    CURRENT_TIMESTAMP
);
