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
--   redis-cli --eval token_bucket.lua ratelimit:1.2.3.4 , 20 5 1700000000000 60000 1
--
-- KEYS[1] -- the bucket key.
-- ARGV[1] -- burst: bucket capacity, in tokens.
-- ARGV[2] -- rate: tokens replenished per second. Zero means never.
-- ARGV[3] -- now_ms: caller's clock, in milliseconds since the epoch.
-- ARGV[4] -- ttl_ms: how long to keep the bucket after this call.
-- ARGV[5] -- cost: tokens this call consumes. At least 1.
--
-- The cost is deducted here rather than by calling this script `cost` times,
-- because the whole point of running in Redis is that read, refill, decide and
-- write-back are one indivisible step. Looping would reintroduce exactly the
-- interleaving described above, and would also allow a partial deduction: a
-- caller charged for three of five tokens and then denied has paid for work it
-- was not allowed to do.
--
-- Returns {allowed, remaining, retry_after_ms}:
--   allowed        1 if the full cost was consumed, 0 if not.
--   remaining      whole tokens left after this call.
--   retry_after_ms milliseconds until the caller may proceed; 0 if it may now,
--                  -1 if the bucket never refills.

local key    = KEYS[1]
local burst  = tonumber(ARGV[1])
local rate   = tonumber(ARGV[2])
local now_ms = tonumber(ARGV[3])
local ttl_ms = tonumber(ARGV[4])
local cost   = tonumber(ARGV[5])

-- A cost below 1 would let a miscomputed weight buy a free request.
if cost == nil or cost < 1 then
  cost = 1
end

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

-- All of the cost or none of it. A cost above burst can never be met, which is
-- a denial rather than an error: the bucket simply cannot hold that much.
local allowed = 0
if tokens >= cost then
  allowed = 1
  tokens = tokens - cost
end

-- How many tokens the caller still needs before it may proceed. After a
-- successful take that is one token, for the next single request; after a
-- denial it is the remainder of this call's cost, so a client that comes back
-- at the advertised time is not rejected a second time.
local needed = 0
if allowed == 1 then
  if tokens < 1 then
    needed = 1 - tokens
  end
else
  needed = cost - tokens
end

local retry_ms = 0
if needed > 0 then
  if rate > 0 then
    -- Round up. Advertising a retry time at which the token is not yet
    -- available just invites the client back into another rejection.
    retry_ms = math.ceil((needed / rate) * 1000)
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

-- math.max guards the floor against a negative remainder, which cannot happen
-- with the clamp above but would be a silent contract violation if it did.
return {allowed, math.max(0, math.floor(tokens)), retry_ms}
