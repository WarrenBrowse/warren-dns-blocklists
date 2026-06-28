-- Executable test for the destination-decode logic in kresd.conf.
--
-- kresd runs on LuaJIT; this harness mocks the kresd globals (net, policy,
-- modules, option, log_level) and a sockaddr-like object (:family()/:ip()
-- via real FFI), then loads the REAL kresd.conf and exercises the captured
-- filtering rule. It validates the parts most likely to be wrong without a
-- live exit: the FFI byte access, the 100.64.0.0/24 gate, the last-octet
-- bitmask decode, and the per-category dispatch.
--
-- Run: luajit test-kresd-decode.lua   (kresd.conf is located next to this file)

local ffi = require('ffi')
local bit = require('bit')

local captured_rules = {}
local rpz_loaded = {}
local listeners = {}

-- Mock kresd globals used by kresd.conf.
_G.net = { listen = function(addr, port, opts) listeners[#listeners + 1] = addr end }
_G.modules = {}
_G.option = function() end
_G.log_level = function() end
_G.policy = {
    DENY = { deny = true },
    DENY_MSG = function(msg) return { deny = msg } end,
    suffix = function(action, _names) return function() return nil end end,
    todnames = function(t) return t end,
    -- Return a matcher closure. To prove per-category dispatch, the ads zone
    -- "blocks" doubleclick.net and the malware zone "blocks" evil.test; every
    -- other zone blocks nothing.
    rpz = function(action, path, _watch)
        rpz_loaded[#rpz_loaded + 1] = path
        return function(_, query)
            if path:match('ads%.rpz$') and query.name == 'doubleclick.net' then
                return action
            end
            if path:match('malware%.rpz$') and query.name == 'evil.test' then
                return action
            end
            return nil
        end
    end,
    add = function(rule) captured_rules[#captured_rules + 1] = rule end,
}

-- A sockaddr stand-in: :family() and :ip() match how kresd's view module
-- consumes req.qsource.dst_addr (addr:ip() yields raw network-order bytes).
local function mock_addr(o1, o2, o3, o4, family)
    local buf = ffi.new('uint8_t[4]', o1, o2, o3, o4)
    return {
        family = function() return family or 2 end, -- AF_INET = 2
        ip = function() return buf end,
    }
end

-- Resolve kresd.conf relative to this script so the test runs from any cwd
-- and in both layouts (this standalone repo, or warren-core's infra/dns/).
local here = (arg and arg[0] and arg[0]:match('^(.*)[/\\]')) or '.'
dofile(here .. '/kresd.conf')

assert(#listeners == 64, 'expected 64 listeners (10.66.0.1 + 100.64.0.1..63), got ' .. #listeners)
assert(#rpz_loaded == 6, 'expected 6 RPZ zones loaded once, got ' .. #rpz_loaded)

local decode = captured_rules[1]
assert(decode ~= nil, 'no filtering rule captured from policy.add')

local function run(addr, qname)
    return decode({ qsource = { dst_addr = addr } }, { name = qname })
end

local function check(desc, cond)
    if not cond then
        error('FAIL: ' .. desc, 2)
    end
    print('  ok: ' .. desc)
end

-- ads bit (.1) blocks an ads domain
check('100.64.0.1 (ads) blocks doubleclick.net', run(mock_addr(100, 64, 0, 1), 'doubleclick.net') ~= nil)
-- trackers-only (.2) must NOT block an ads domain -> proves per-category, not union
check('100.64.0.2 (trackers only) does NOT block an ads domain', run(mock_addr(100, 64, 0, 2), 'doubleclick.net') == nil)
-- combined ads+malware (.5) blocks both lists
check('100.64.0.5 (ads|malware) blocks doubleclick.net', run(mock_addr(100, 64, 0, 5), 'doubleclick.net') ~= nil)
check('100.64.0.5 (ads|malware) blocks evil.test', run(mock_addr(100, 64, 0, 5), 'evil.test') ~= nil)
-- malware-only (.4) does not block an ads domain, blocks malware
check('100.64.0.4 (malware only) does NOT block doubleclick.net', run(mock_addr(100, 64, 0, 4), 'doubleclick.net') == nil)
check('100.64.0.4 (malware only) blocks evil.test', run(mock_addr(100, 64, 0, 4), 'evil.test') ~= nil)
-- all bits (.63) blocks everything listed
check('100.64.0.63 (all) blocks doubleclick.net', run(mock_addr(100, 64, 0, 63), 'doubleclick.net') ~= nil)
-- vanilla gateway never filters
check('10.66.0.1 (vanilla) never filters', run(mock_addr(10, 66, 0, 1), 'doubleclick.net') == nil)
-- outside the /24 never filters
check('100.64.1.1 (outside /24) never filters', run(mock_addr(100, 64, 1, 1), 'doubleclick.net') == nil)
-- a non-listed domain resolves even on a block address
check('100.64.0.63 lets a non-listed domain through', run(mock_addr(100, 64, 0, 63), 'example.com') == nil)
-- IPv6 family -> treated as vanilla (daemon only composes IPv4)
check('IPv6-family query is treated as vanilla', run(mock_addr(100, 64, 0, 1, 10), 'doubleclick.net') == nil)

print('ALL kresd decode assertions passed (' .. #listeners .. ' listeners, ' .. #rpz_loaded .. ' zones)')
