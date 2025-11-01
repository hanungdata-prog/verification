-- Create verifications table for AuthGateway
-- Run this SQL in your Supabase SQL Editor

CREATE TABLE IF NOT EXISTS verifications (
    id BIGINT PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    discord_id VARCHAR(20) NOT NULL,
    discord_username VARCHAR(100) NOT NULL,
    ip_address TEXT NOT NULL, -- This will be encrypted
    user_agent TEXT,
    method VARCHAR(50) DEFAULT 'captcha',
    verification_id VARCHAR(50) NOT NULL UNIQUE,
    extra_data JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    verified_at TIMESTAMPTZ DEFAULT NOW()
);

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_verifications_discord_id ON verifications(discord_id);
CREATE INDEX IF NOT EXISTS idx_verifications_created_at ON verifications(created_at);
CREATE INDEX IF NOT EXISTS idx_verifications_verification_id ON verifications(verification_id);

-- Enable Row Level Security (RLS)
ALTER TABLE verifications ENABLE ROW LEVEL SECURITY;

-- Create policy for read access (admin only - implement as needed)
CREATE POLICY "Admin can view all verifications" ON verifications
    FOR SELECT USING (true);

-- Create policy for insert operations (allow public inserts for verification)
CREATE POLICY "Allow verification inserts" ON verifications
    FOR INSERT WITH CHECK (true);

-- Add comments for documentation
COMMENT ON TABLE verifications IS 'Stores user verification data from AuthGateway system';
COMMENT ON COLUMN verifications.discord_id IS 'Discord user ID (17-20 digits)';
COMMENT ON COLUMN verifications.discord_username IS 'Discord username with discriminator';
COMMENT ON COLUMN verifications.ip_address IS 'Encrypted IP address of the user';
COMMENT ON COLUMN verifications.user_agent IS 'Browser user agent string';
COMMENT ON COLUMN verifications.method IS 'Verification method used (captcha, oauth, etc.)';
COMMENT ON COLUMN verifications.verification_id IS 'Unique verification token';
COMMENT ON COLUMN verifications.extra_data IS 'Additional metadata in JSON format';
COMMENT ON COLUMN verifications.created_at IS 'When the verification record was created';
COMMENT ON COLUMN verifications.verified_at IS 'When the verification was completed';