-- token_bucket.lua -- one atomic token-bucket decision.
--
-- This runs inside Redis so that read, refill, decide and write-back happen as
-- a single indivisible step. Doing the same work from Go would take two round
-- trips, and between them another request on the same key reads the same
-- pre-decrement state. Under concurrency every one of those requests sees
-- tokens available and every one is admitted, so the effective limit becomes
-- "burst per round trip" instead of "burst". That is not a rare race: it is the
-- normal case whenever a client opens several connections at once, which is
-- exactly what an attacker does.
--
-- The file is standalone rather than a Go string constant so that it can be
-- linted, read with syntax highlighting, and run directly against a server
-- while debugging:
--
--   redis-cli --eval token_bucket.lua ratelimit:1.2.3.4 , 20 5 1700000000000 60000
--
-- KEYS[1] -- the bucket key.
-- ARGV[1] -- burst: bucket capacity, in tokens.
-- ARGV[2] -- rate: tokens replenished per second. Zero means never.
-- ARGV[3] -- now_ms: caller's clock, in milliseconds since the epoch.
-- ARGV[4] -- ttl_ms: how long to keep the bucket after this call.
--
-- Returns {allowed, remaining, retry_after_ms}:
--   allowed        1 if a token was consumed, 0 if not.
--   remaining      whole tokens left after this call.
--   retry_after_ms milliseconds until a token is available; 0 if one is
--                  available now, -1 if the bucket never refills.

local key    = KEYS[1]
local burst  = tonumber(ARGV[1])
local rate   = tonumber(ARGV[2])
local now_ms = tonumber(ARGV[3])
local ttl_ms = tonumber(ARGV[4])

-- State is one hash rather than two keys: it expires as a unit, it is written
-- as a unit, and in cluster mode it lives in a single slot.
local state  = redis.call('HMGET', key, 't', 'ts')
local tokens = tonumber(state[1])
local last   = tonumber(state[2])

if tokens == nil or last == nil then
  -- An unknown key is a full bucket. A new client is not a throttled client.
  tokens = burst
  last = now_ms
end

-- Refill only for time that has actually passed. A negative elapsed value means
-- the caller's clock is behind the one that last wrote this key -- clock skew
-- between application instances, or an NTP step. Crediting tokens for it would
-- hand out free allowance, so it credits nothing instead. That errs toward
-- over-restricting, which is the right direction for a limit.
local elapsed_ms = now_ms - last
if elapsed_ms > 0 and rate > 0 then
  tokens = tokens + (elapsed_ms / 1000.0) * rate
end

if tokens > burst then
  tokens = burst
end
if tokens < 0 then
  tokens = 0
end

local allowed = 0
if tokens >= 1 then
  allowed = 1
  tokens = tokens - 1
end

local retry_ms = 0
if tokens < 1 then
  if rate > 0 then
    -- Round up. Advertising a retry time at which the token is not yet
    -- available just invites the client back into another rejection.
    retry_ms = math.ceil(((1 - tokens) / rate) * 1000)
    if retry_ms < 1 then
      retry_ms = 1
    end
  else
    retry_ms = -1
  end
end

-- tostring, not the bare number: Redis converts Lua numbers passed to
-- redis.call into integers, which would silently truncate the fractional part
-- of the token count and lose every partial refill.
redis.call('HSET', key, 't', tostring(tokens), 'ts', tostring(now_ms))

-- Expiry in Redis replaces the janitor an in-process store would need. The
-- caller sizes the TTL so that a bucket is never dropped before it would have
-- refilled -- dropping one early resets its client's allowance.
redis.call('PEXPIRE', key, ttl_ms)

return {allowed, math.floor(tokens), retry_ms}
