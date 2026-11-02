--[[
  string_dump.luau — VM-aware string dumper (multi-phase): bytecode.const + buffer/bit32/loadstring hooks + thick env
  Sources: FULL string.* (char/format/gsub/sub/rep/match/gmatch/find/split/pack/unpack/lower/upper/reverse)
           | tostring | utf8.char | buffer.* | crypt/base64 UNC | xor-strtab | HttpGet/loadstring | api-arg | print
  Usage: lune run string_dump.luau <input.lua> [output.txt]
]]
local fs = require("@lune/fs")
local process = require("@lune/process")
local luau = require("@lune/luau")

-- ===== RobloxFidelity (optional thick env) =====
-- Looks next to lupro: RobloxFidelity.luau OR Libraries/RobloxFidelity.luau
local Fidelity = nil
do
	local function tryRequire(path)
		local ok, mod = pcall(require, path)
		if ok and type(mod) == "table" and mod.ToFloat32 ~= nil then
			return mod
		end
		return nil
	end
	local function tryLoadFile(path)
		if type(fs) ~= "table" or type(fs.isFile) ~= "function" then return nil end
		if not fs.isFile(path) then return nil end
		local okR, src = pcall(fs.readFile, path)
		if not okR or type(src) ~= "string" or #src < 100 then return nil end
		local okL, chunk = pcall(luau.load, src, { debugName = "rf" })
		if not okL or type(chunk) ~= "function" then return nil end
		local okC, mod = pcall(chunk)
		if okC and type(mod) == "table" and mod.ToFloat32 ~= nil then
			return mod
		end
		return nil
	end
	local cwd = (type(process) == "table" and type(process.cwd) == "string" and process.cwd) or "."
	local names = {
		"RobloxFidelity.luau",
		"RobloxFidelity.lua",
		"Libraries/RobloxFidelity.luau",
		"Libraries/RobloxFidelity.lua",
		"Libraries/RobloxFidelity",
		"./RobloxFidelity.luau",
		"./Libraries/RobloxFidelity.luau",
	}
	local requireNames = {
		"./RobloxFidelity",
		"RobloxFidelity",
		"./Libraries/RobloxFidelity",
		"Libraries/RobloxFidelity",
	}
	for _, n in ipairs(requireNames) do
		Fidelity = tryRequire(n)
		if Fidelity then break end
	end
	if not Fidelity then
		for _, n in ipairs(names) do
			Fidelity = tryLoadFile(n)
			if Fidelity then break end
			Fidelity = tryLoadFile(cwd .. "/" .. n)
			if Fidelity then break end
		end
	end
end

local args = process.args
local inputPath, outputPath = args[1], args[2]
if not inputPath then
	print("usage: lune run string_dump.luau <input.lua> [output.txt]")
	process.exit(1)
end
local okR, source = pcall(fs.readFile, inputPath)
if not okR or type(source) ~= "string" then
	print("cannot read input")
	process.exit(1)
end

local BUDGET = 60
local started = os.clock()
local dumpDead = false
local function dumpCheck()
	if dumpDead then return true end
	if os.clock() - started > BUDGET then dumpDead = true return true end
	return false
end
local lines, seen, charBuf, utf8Buf = {}, {}, {}, {}

-- Accept almost any printable / mixed string (minimal filter)
local function interesting(s)
	if type(s) ~= "string" then return false end
	local n = #s
	if n < 1 or n > 8000 then return false end
	-- reject pure whitespace
	if string.match(s, "^%s*$") then return false end
	-- reject single digit-only noise under 2 chars unless letter
	if n == 1 and not string.match(s, "%a") then return false end
	return true
end

local function tagFor(s)
	if string.match(s, "^https?://") or string.match(s, "^[%w%-]+%.[%w%.%-]+/") then return "URL" end
	if string.match(s, "^[A-Z][%w]+$") and #s >= 4 then return "KEY_OR_TOKEN" end
	if string.match(s, "^[%l]+[%u]%w*$") then return "KEY_OR_TOKEN" end
	if string.match(s, "^[%w_]+/[%w%._%-]+") then return "PATH" end
	if #s >= 16 and string.match(s, "^[%w%+/=]+$") then return "TOKEN" end
	if string.match(s, "[%z\1-\8\11\12\14-\31]") then return "BINARY" end
	return "CONST"
end

local emitIndex = 0
local function emit(src, s)
	if not interesting(s) then return end
	if s == "Player" or s == "LocalPlayer" or s == "nil" then return end
	if src == "prop:Name" and (s == "Player" or s == "Workspace" or s == "game") then return end
	local flat = string.gsub(s, "[\r\n]+", "\\n")
	if string.match(flat, "[%z\1-\8\11\12\14-\31]") then
		flat = (string.gsub(flat, ".", function(c)
			local b = string.byte(c)
			if b < 32 or b > 126 then return string.format("\\%d", b) end
			return c
		end))
	end
	if #flat > 8000 then flat = string.sub(flat, 1, 8000) .. "…" end
	local key = flat
	if seen[key] then return end
	seen[key] = true
	emitIndex += 1
	if string.find(flat, "attempt to perform arithmetic", 1, true) then return end
	if string.find(flat, "[string ", 1, true) then return end
	-- drop huge raw pool blobs / junk
	if #flat > 400 then return end
	if (string.find(flat, "wearedevs.meta", 1, true)) then return end
	lines[#lines + 1] = string.format("[%d] = %s", emitIndex, flat)
end


-- Deep harvest strings from any source blob (loadstring / nested VM text)
local function harvestCode(blob, tag)
	if type(blob) ~= "string" or #blob < 2 then return end
	tag = tag or "code"
	-- quoted strings
	for s in string.gmatch(blob, '"((?:\\.|[^"\\])*)"') do
		local ok, u = pcall(function()
			return (string.gsub(s, "\\(%d%d?%d?)", function(n)
				local v = tonumber(n)
				if v and v <= 255 then return string.char(v) end
				return ""
			end))
		end)
		if ok and type(u) == "string" and #u >= 2 then emit(tag .. ":quote", u) end
	end
	for s in string.gmatch(blob, "'((?:\\.|[^'\\])*)'") do
		if #s >= 2 then emit(tag .. ":quote", s) end
	end
	-- long strings
	for s in string.gmatch(blob, "%[%[(.-)%]%]") do
		if #s >= 2 then emit(tag .. ":long", s) end
	end
	-- string.char(1,2,3)
	for chunk in string.gmatch(blob, "string%.char%s*%(([%d%s,]+)%)") do
		local bytes = {}
		for n in string.gmatch(chunk, "%d+") do
			local b = tonumber(n)
			if b and b <= 255 then bytes[#bytes + 1] = b end
		end
		if #bytes >= 2 then
			local ok, decoded = pcall(string.char, table.unpack(bytes))
			if ok and decoded then emit(tag .. ":char", decoded) end
		end
	end
	-- \ddd sequences
	for esc in string.gmatch(blob, "(?:\\%d%d%d){3,}") do
		local bytes = {}
		for n in string.gmatch(esc, "\\(%d%d%d)") do
			local b = tonumber(n)
			if b and b <= 255 then bytes[#bytes + 1] = b end
		end
		if #bytes >= 3 then
			local ok, decoded = pcall(string.char, table.unpack(bytes))
			if ok and decoded then emit(tag .. ":esc", decoded) end
		end
	end
end

-- ===== XOR string-table (multi-strategy) =====
local function recoverXor(src)
	local arrays, nArr = {}, 0
	for arr in string.gmatch(src, "%{([%d,%s]+)%}") do
		local nums, ok, n = {}, true, 0
		for tok in string.gmatch(arr, "%d+") do
			local v = tonumber(tok)
			if not v or v > 255 then ok = false break end
			n += 1; nums[n] = v
		end
		if ok and n >= 2 and n <= 256 then nArr += 1; arrays[nArr] = nums end
	end
	if nArr < 6 then return 0 end

	local function tryDec(srcArr, keys, reverseKeys)
		local n = #srcArr
		local buf = table.create(n)
		for j = 1, n do buf[j] = srcArr[j] end
		local order = {}
		if reverseKeys then
			for L = #keys, 1, -1 do order[#order + 1] = keys[L] end
		else
			for L = 1, #keys do order[#order + 1] = keys[L] end
		end
		for _, kk in ipairs(order) do
			local kl = #kk
			if kl > 0 then
				for j = 1, n do buf[j] = bit32.bxor(buf[j] % 256, kk[((j - 1) % kl) + 1] % 256) end
			end
		end
		for j = 1, n do buf[j] = string.char(buf[j] % 256) end
		return table.concat(buf)
	end

	local function scoreStr(s)
		if type(s) ~= "string" or #s < 3 or #s > 80 then return 0 end
		-- require mostly printable
		local okc = 0
		for i = 1, #s do
			local b = string.byte(s, i)
			if b >= 32 and b < 127 then okc += 1 end
		end
		if okc < #s then return 0 end
		if string.match(s, "^https?://") then return 8 end
		-- strong Roblox-like identifiers only (avoid "xC" junk)
		if string.match(s, "^[A-Z][%a%d][%a%d_]+$") then return 6 end
		if string.match(s, "^[%l]+[%u][%a%d_]*$") then return 6 end
		if string.match(s, "^[%l][%a%d_][%a%d_][%a%d_]+$") then return 4 end
		if string.match(s, "^[%a_][%w_]+$") and #s >= 5 then return 3 end
		return 0
	end

	local best, bestScore = {}, 0
	for reverseKeys = 0, 1 do
		for kc = 1, math.min(48, nArr - 3) do
			if os.clock() - started > BUDGET * 0.35 then break end
			local keys = {}
			for i = nArr - kc + 1, nArr do
				if arrays[i] and #arrays[i] >= 6 and #arrays[i] <= 128 then
					keys[#keys + 1] = arrays[i]
				end
			end
			if #keys == 0 then
				for i = nArr - kc + 1, nArr do keys[#keys + 1] = arrays[i] end
			end
			if #keys == 0 then break end
			local score, recovered, tried = 0, {}, 0
			for i = 1, nArr - kc do
				local a = arrays[i]
				if a and #a >= 2 and #a <= 64 then
					tried += 1
					if tried > 900 then break end
					local s = tryDec(a, keys, reverseKeys == 1)
					local sc = scoreStr(s)
					if sc > 0 then
						score += sc
						recovered[#recovered + 1] = s
					end
				end
			end
			if score > bestScore and #recovered >= 5 then
				bestScore = score
				best = recovered
			end
			if bestScore >= 100 then break end
		end
		if bestScore >= 100 then break end
	end

	-- also try single-key XOR (first/last long arrays as key)
	for _, keyIdx in ipairs({ nArr, nArr - 1, 1, 2 }) do
		if keyIdx >= 1 and keyIdx <= nArr and arrays[keyIdx] and #arrays[keyIdx] >= 8 then
			local keys = { arrays[keyIdx] }
			local score, recovered, tried = 0, {}, 0
			for i = 1, nArr do
				if i ~= keyIdx then
					local a = arrays[i]
					if a and #a >= 2 and #a <= 64 then
						tried += 1
						if tried > 400 then break end
						local s = tryDec(a, keys, true)
						local sc = scoreStr(s)
						if sc > 0 then score += sc; recovered[#recovered + 1] = s end
					end
				end
			end
			if score > bestScore and #recovered >= 5 then
				bestScore = score
				best = recovered
			end
		end
	end

	local n = 0
	if bestScore >= 25 then
		for _, s in ipairs(best) do emit("xor-strtab", s); n += 1 end
	end
	return n
end

-- Static harvest: URLs + PascalCase / Roblox-like tokens only (no cipher soup)
do
	local function goodId(s)
		if type(s) ~= "string" or #s < 4 or #s > 80 then return false end
		-- must contain a vowel to drop random tokens like XJo8 / bZfx
		if not string.match(string.lower(s), "[aeiou]") then return false end
		-- digit ratio low
		local digits = 0
		for i = 1, #s do
			if string.match(string.sub(s, i, i), "%d") then digits = digits + 1 end
		end
		if digits > #s / 3 then return false end
		if string.match(s, "^[A-Z][%a]+[a-z][%a]*$") and #s >= 5 then return true end
		if string.match(s, "^[%l]+[%u]%a+$") and #s >= 5 then return true end
		if s == "game" or s == "workspace" or s == "script" or s == "shared" then return true end
		if s == "wait" or s == "spawn" or s == "delay" or s == "defer" or s == "cancel" then return true end
		return false
	end
	for s in string.gmatch(source, '"([^"]+)"') do
		if string.match(s, "^https?://") then emit("static:url", s)
		elseif goodId(s) then emit("static:id", s) end
	end
	for s in string.gmatch(source, "'([^']+)'") do
		if goodId(s) then emit("static:id", s) end
	end
	-- LPH watermark / version strings
	for s in string.gmatch(source, '"(LPH:[^"]*)"') do
		emit("static:lph", s)
	end
end

pcall(harvestCode, source, "static")

-- WEAREDEVS_FULL_DECODE_WXZ: fully decode T*/m* string pool without running VM
do
	local function wrdExtractArray(src)
		-- match: local c={ ... } at start of WeAreDevs blob
		local i = string.find(src, "local%s+[%w_]+%s*=%s*{", 1)
		if not i then return nil end
		local depth, j = 0, i
		local startBrace = string.find(src, "{", i, true)
		if not startBrace then return nil end
		j = startBrace
		depth = 1
		j = j + 1
		while j <= #src and depth > 0 do
			local ch = string.sub(src, j, j)
			if ch == "{" then depth = depth + 1
			elseif ch == "}" then depth = depth - 1
			elseif ch == '"' or ch == "'" then
				local q = ch
				j = j + 1
				while j <= #src do
					local c2 = string.sub(src, j, j)
					if c2 == "\\" then j = j + 2
					elseif c2 == q then break
					else j = j + 1 end
				end
			end
			j = j + 1
		end
		return string.sub(src, startBrace, j - 1)
	end

	local function wrdParseStrings(arrLit)
		local out = {}
		local i = 1
		while i <= #arrLit do
			local c = string.sub(arrLit, i, i)
			if c == '"' then
				local buf = {}
				i = i + 1
				while i <= #arrLit do
					local ch = string.sub(arrLit, i, i)
					if ch == "\\" then
						local n = string.sub(arrLit, i + 1, i + 1)
						if n == "n" then buf[#buf+1] = "\n"; i = i + 2
						elseif n == "t" then buf[#buf+1] = "\t"; i = i + 2
						elseif n == "r" then buf[#buf+1] = "\r"; i = i + 2
						elseif n == '"' then buf[#buf+1] = '"'; i = i + 2
						elseif n == "\\" then buf[#buf+1] = "\\"; i = i + 2
						elseif n == "'" then buf[#buf+1] = "'"; i = i + 2
						else buf[#buf+1] = n; i = i + 2 end
					elseif ch == '"' then
						i = i + 1
						break
					else
						buf[#buf+1] = ch
						i = i + 1
					end
				end
				out[#out+1] = table.concat(buf)
			else
				i = i + 1
			end
		end
		return out
	end

	-- Alphabet maps reconstructed from typical WeAreDevs v1 payloads (numeric consts folded)
	-- Runtime may differ slightly per build; we also eval maps from source when possible.
	local function buildMapFromSource(src, marker)
		-- very rough: not always present as clear table; fallback to runtime decode path
		return nil
	end

	local function decodeT(body, mapO)
		-- T-encoding: variable-width radix using mapO values, pack to bytes
		if type(body) ~= "string" or #body < 1 then return nil end
		local out = {}
		local t = 1
		local W = #body
		while t <= W do
			local remain = (W - t) + 1
			local U = remain >= 5 and 5 or remain
			local s = 0
			local ok = U > 1
			for c = 0, 4 do
				local Wch
				if c < U then
					local ch = string.sub(body, t + c, t + c)
					Wch = mapO[ch]
					if type(Wch) == "string" then Wch = tonumber(Wch) end
					if type(Wch) ~= "number" then ok = false break end
				else
					Wch = 84 -- padding sentinel used in VM
				end
				s = s * 85 + Wch
			end
			if ok then
				local b0 = math.floor(s / 16777216) % 256
				local b1 = math.floor(s / 65536) % 256
				local b2 = math.floor(s / 256) % 256
				local b3 = s % 256
				if U == 5 then
					out[#out+1] = string.char(b0, b1, b2, b3)
				elseif U == 4 then
					out[#out+1] = string.char(b0, b1, b2)
				elseif U == 3 then
					out[#out+1] = string.char(b0, b1)
				elseif U == 2 then
					out[#out+1] = string.char(b0)
				end
			end
			t = t + U
		end
		local r = table.concat(out)
		return #r > 0 and r or nil
	end

	local function decodeM(body, mapK)
		-- m-encoding: base64-like groups of 4 → 3 bytes (no ^ to avoid string/number pow)
		if type(body) ~= "string" or #body < 1 then return nil end
		local out = {}
		local t = 1
		local O = #body
		local N, M = 0, 0
		local pow64 = { [0] = 262144, [1] = 4096, [2] = 64, [3] = 1 }
		while t <= O do
			local ch = string.sub(body, t, t)
			local U = mapK[ch]
			if type(U) == "string" then U = tonumber(U) end
			if type(U) == "number" then
				local mul = pow64[M] or 1
				N = N + (U * mul)
				M = M + 1
				if M == 4 then
					M = 0
					local c = math.floor(N / 65536) % 256
					local u = math.floor(N / 256) % 256
					local o = N % 256
					if c >= 0 and c < 256 and u >= 0 and u < 256 and o >= 0 and o < 256 then
						out[#out+1] = string.char(c, u, o)
					end
					N = 0
				end
			elseif ch == "=" then
				local c = math.floor(N / 65536) % 256
				out[#out+1] = string.char(c)
				if t >= O or string.sub(body, t + 1, t + 1) ~= "=" then
					local u = math.floor((N % 65536) / 256) % 256
					out[#out+1] = string.char(u)
				end
				break
			end
			t = t + 1
		end
		local r = table.concat(out)
		return #r > 0 and r or nil
	end

	-- Fold simple integer expressions like -601459+601460 or 113623830%714615
	local function foldExpr(e)
		e = string.gsub(e, "%s+", "")
		if not string.match(e, "^[%d%+%-%*%%/()]+$") then return nil end
		local ok2, f2 = pcall(luau.load, "return (" .. e .. ")", { debugName = "f" })
		if not ok2 or type(f2) ~= "function" then return nil end
		local ok, v = pcall(f2)
		if ok and type(v) == "number" then return v end
		return nil
	end

	local function extractCharMap(src, which)
		-- Find alphabet table near decode: local O={m=...,["$"]=...} or K={j=...}
		-- Heuristic: largest { key=number / ["x"]=number } block after "local"
		local best, bestN = nil, 0
		for block in string.gmatch(src, "local%s+[%w_]+%s*=%s*(%b{})") do
			local n = 0
			local map = {}
			for k, v in string.gmatch(block, "%[\"([^\"]+)\"%]%s*=%s*([%d%+%-%*%%/()]+)") do
				local num = foldExpr(v)
				if num then map[k] = num; n = n + 1 end
			end
			for k, v in string.gmatch(block, "([%a_])%s*=%s*([%d%+%-%*%%/()]+)") do
				local num = foldExpr(v)
				if num then map[k] = num; n = n + 1 end
			end
			if n > bestN then bestN, best = n, map end
		end
		return best, bestN
	end

	if string.find(source, "wearedevs%.net/obfuscator", 1, true) or string.find(source, 'local c={"T', 1, true) then
		emit("bytecode.const", "wearedevs")
		local arrLit = wrdExtractArray(source)
		local tokens = arrLit and wrdParseStrings(arrLit) or {}
		-- extract both maps (O for T, K for m) — take two largest maps
		local maps = {}
		for block in string.gmatch(source, "local%s+[%w_]+%s*=%s*(%b{})") do
			local map, n = {}, 0
			for k, v in string.gmatch(block, "%[\"([^\"]+)\"%]%s*=%s*([%d%+%-%*%%/()%-]+)") do
				local num = foldExpr(v)
				if num then map[k] = num; n = n + 1 end
			end
			for k, v in string.gmatch(block, "([%a_])%s*=%s*([%d%+%-%*%%/()%-]+)") do
				local num = foldExpr(v)
				if num then map[k] = num; n = n + 1 end
			end
			if n >= 20 then maps[#maps+1] = { n = n, map = map } end
		end
		table.sort(maps, function(a, b) return a.n > b.n end)
		local function scorePlain(s)
			if type(s) ~= "string" or #s < 1 then return -1 end
			local good = 0
			for i = 1, #s do
				local b = string.byte(s, i)
				if b >= 32 and b < 127 then good = good + 1
				elseif b == 9 or b == 10 or b == 13 then good = good + 1
				else good = good - 2 end
			end
			return good
		end

		-- Per-token: try both map orderings, keep best printable decode
		local m1 = maps[1] and maps[1].map or {}
		local m2 = maps[2] and maps[2].map or m1
		local decoded = 0
		local seenPlain = {}
		for _, tok in ipairs(tokens) do
			if #tok >= 2 then
				local tag = string.sub(tok, 1, 1)
				local body = string.sub(tok, 2)
				local candidates = {}
				if tag == "T" then
					candidates[#candidates+1] = decodeT(body, m1)
					candidates[#candidates+1] = decodeT(body, m2)
				elseif tag == "m" then
					candidates[#candidates+1] = decodeM(body, m1)
					candidates[#candidates+1] = decodeM(body, m2)
				end
				local bestPlain, bestSc = nil, -1
				for _, plain in ipairs(candidates) do
					local sc = scorePlain(plain)
					if sc > bestSc then
						bestSc, bestPlain = sc, plain
					end
				end
				if type(bestPlain) == "string" and bestSc >= math.max(1, math.floor(#bestPlain * 0.55)) then
					if not seenPlain[bestPlain] then
						seenPlain[bestPlain] = true
						emit("wearedevs.decoded", bestPlain)
						decoded = decoded + 1
						pcall(harvestCode, bestPlain, "wrd")
					end
				end
			end
		end
		-- also emit raw tokens that look like already-plain identifiers (rare)
		-- meta only in log via print skipped for clean out
	end
end




-- ===== bytecode.const (Luraph / Luau constant & lib.member scan) =====
-- Matches AZT-style dumps: library field names + known globals embedded in VM blobs
do
	local KNOWN = {
		-- Luau base libs
		setmetatable=true, getmetatable=true, rawset=true, rawget=true, rawequal=true, rawlen=true,
		pcall=true, xpcall=true, error=true, assert=true, type=true, typeof=true, tostring=true, tonumber=true,
		select=true, unpack=true, pairs=true, ipairs=true, next=true, print=true, require=true,
		loadstring=true, load=true, newproxy=true, gcinfo=true, collectgarbage=true,
		-- libs
		string=true, table=true, math=true, bit32=true, buffer=true, coroutine=true, debug=true, utf8=true, os=true, task=true,
		-- string
		byte=true, char=true, find=true, format=true, gmatch=true, gsub=true, len=true, lower=true, match=true,
		pack=true, packsize=true, rep=true, reverse=true, split=true, sub=true, upper=true,
		-- table
		concat=true, insert=true, remove=true, sort=true, clear=true, create=true, move=true, freeze=true, clone=true,
		-- bit32
		band=true, bor=true, bxor=true, bnot=true, lshift=true, rshift=true, arshift=true, lrotate=true, rrotate=true,
		countlz=true, countrz=true, extract=true, replace=true,
		-- buffer
		fromstring=true, readstring=true, writestring=true, readi8=true, readu8=true, readi16=true, readu16=true,
		readi32=true, readu32=true, readf32=true, readf64=true, writei8=true, writeu8=true, writei16=true, writeu16=true,
		writei32=true, writeu32=true, writef32=true, writef64=true, readbits=true, writebits=true, fill=true, copy=true,
		-- coroutine
		yield=true, resume=true, status=true, running=true, wrap=true, isyieldable=true, close=true, create=true,
		-- debug
		info=true, traceback=true, getinfo=true, profilebegin=true, profileend=true,
		-- task
		wait=true, spawn=true, defer=true, delay=true, cancel=true, synchronize=true, desynchronize=true,
		-- Roblox types / globals often in const pool
		Instance=true, game=true, workspace=true, Workspace=true, script=true, shared=true,
		Vector2=true, Vector3=true, CFrame=true, Color3=true, UDim=true, UDim2=true, Ray=true, Region3=true,
		BrickColor=true, Enum=true, Random=true, NumberRange=true, NumberSequence=true, ColorSequence=true,
		TweenInfo=true, Path2DControlPoint=true, Path2D=true, Axes=true, Faces=true, Rect=true,
		OverlapParams=true, RaycastParams=true, PhysicalProperties=true, Font=true, DateTime=true,
		-- metatable / common
		__index=true, __newindex=true, __call=true, __tostring=true, __len=true, __mode=true,
		Parent=true, Name=true, ClassName=true, Folder=true, ScreenGui=true, Frame=true, Part=true, Model=true,
		-- executor
		islclosure=true, iscclosure=true, newcclosure=true, checkcaller=true, getgenv=true, getrenv=true,
		scratch=true, isvararg=true, what=true, namewhat=true, short_src=true, currentline=true,
		Folder=true, ScreenGui=true, Frame=true, Path2D=true, TextLabel=true, TextButton=true,
		RemoteEvent=true, RemoteFunction=true, BindableEvent=true, BindableFunction=true,
		Humanoid=true, Players=true, LocalPlayer=true, GetService=true, WaitForChild=true,
		FindFirstChild=true, Destroy=true, Clone=true, Connect=true, Disconnect=true,
		HTTPService=true, HttpService=true, JSONEncode=true, JSONDecode=true,
		tick=true, time=true, elapsedTime=true, typeof=true, ypcall=true,
		readf32=true, writef64=true, writef32=true, readf64=true,
		arshift=true, extract=true, replace=true, freeze=true, clone=true,
		packsize=true, split=true, upper=true, lower=true, reverse=true,
		remove=true, sort=true, maxn=true, foreach=true, foreachi=true,
		log=true, log10=true, abs=true, floor=true, ceil=true, random=true, noise=true,
		clamp=true, sign=true, round=true, lerp=true, map=true,
		clock=true, date=true, difftime=true,
		getfenv=true, setfenv=true, getrawmetatable=true, setrawmetatable=true,
		checkcaller=true, getgenv=true, getrenv=true, getnamecallmethod=true,

		linedefined=true, lastlinedefined=true, nparams=true, source=true,
	}
	-- Only real library prefixes (avoid cipher.dot.noise)
	local LIBS = {
		buffer=true, bit32=true, bit=true, string=true, table=true, coroutine=true,
		debug=true, utf8=true, math=true, task=true, os=true, game=true, Instance=true,
		workspace=true, Workspace=true, Vector3=true, Vector2=true, CFrame=true, Color3=true,
		UDim2=true, UDim=true, Enum=true, utf8=true,
	}
	-- 1) lib.member: buffer.writei8, bit32.band, string.pack
	for lib, mem in string.gmatch(source, "([%a_][%w_]*)%.([%a_][%w_]*)") do
		if LIBS[lib] and #mem >= 2 and #mem <= 40 then
			emit("bytecode.const", lib)
			emit("bytecode.const", mem)
		end
	end
	-- 2) bare KNOWN tokens (official Luau/Roblox const pool names)
	for word in string.gmatch(source, "[%a_][%w_]+") do
		if KNOWN[word] then
			emit("bytecode.const", word)
		end
	end
	-- 3) quoted constants that are known or clean PascalCase types
	for s in string.gmatch(source, '"([%a_][%w_][%w_][%w_]+)"') do
		if #s <= 48 and KNOWN[s] then
			emit("bytecode.const", s)
		elseif #s >= 4 and #s <= 40 and string.match(s, "^[A-Z][%a]+[a-z][%a]*$") and string.match(string.lower(s), "[aeiou]") then
			emit("bytecode.const", s)
		end
	end
	-- 4) loadstring
	if string.find(source, "loadstring", 1, true) then
		emit("bytecode.const", "loadstring")
	end
end

pcall(recoverXor, source)

-- ===== rich Roblox env =====
local hostChar = string.char
local hostConcat = table.concat
local hostFormat = string.format
local hostGsub = string.gsub
local hostRep = string.rep
local hostSub = string.sub
local hostByte = string.byte

local wordBuf = {}
local function flushWord()
	if #wordBuf == 0 then return end
	local s = table.concat(wordBuf)
	wordBuf = {}
	if #s >= 2 then emit("string.stream", s) end
end
local function pushStreamByte(b)
	if type(b) ~= "number" then return end
	b = b % 256
	if (b >= 32 and b <= 126) or b == 9 then
		wordBuf[#wordBuf + 1] = string.char(b)
		if #wordBuf >= 512 then flushWord() end
	else
		flushWord()
	end
end
local function flushChar()
	if #charBuf == 0 then return end
	local ok, s = pcall(hostChar, table.unpack(charBuf))
	for i = 1, #charBuf do
		pushStreamByte(charBuf[i])
	end
	charBuf = {}
	if ok and type(s) == "string" then emit("string.char[buffered]", s) end
end

local function flushUtf8()
	if #utf8Buf == 0 then return end
	if type(utf8) == "table" and type(utf8.char) == "function" then
		local ok, s = pcall(utf8.char, table.unpack(utf8Buf))
		utf8Buf = {}
		if ok and type(s) == "string" then emit("utf8.char[buffered]", s) end
	else
		utf8Buf = {}
	end
end

local SERVICE_NAMES = {
	"AccountService",
	"AchievementService",
	"ActivityHistoryEventService",
	"AdService",
	"AnalyticsService",
	"AnimatedImageService",
	"AnimationClipProvider",
	"AnimationFromVideoCreatorService",
	"AnimationFromVideoCreatorStudioService",
	"AnnotationsService",
	"AppAgeSignalsService",
	"AppLifecycleObserverService",
	"AppRatingPromptService",
	"AppStorageService",
	"AppUpdateService",
	"AssetCounterService",
	"AssetDeliveryProxy",
	"AssetImportService",
	"AssetManagerService",
	"AssetQualityService",
	"AssetService",
	"AudioFocusService",
	"AvatarChatService",
	"AvatarCreationService",
	"AvatarEditorService",
	"AvatarImportService",
	"AvatarSettings",
	"BackendReplicatedStorage",
	"BackendServerScriptService",
	"BackendServerStorage",
	"BadgeService",
	"BranchService",
	"BrowserService",
	"BugReporterService",
	"BulkImportService",
	"CSGDictionaryService",
	"CacheableContentProvider",
	"CallingService",
	"CalloutService",
	"CaptureService",
	"ChangeHistoryService",
	"ChangeHistoryStreamingService",
	"Chat",
	"ClientStorageService",
	"CloudCRUDService",
	"CloudClientService",
	"CloudExecutionService",
	"ClusterPacketCache",
	"CollaboratorsService",
	"CollectionService",
	"CommerceService",
	"ConfigService",
	"ConfigureServerService",
	"ConnectivityService",
	"ContentProvider",
	"ContextActionService",
	"ControllerService",
	"CookiesService",
	"CoreGui",
	"CoreGuiConfiguration",
	"CorePackages",
	"CoreScriptDebuggingManagerHelper",
	"CoreScriptSyncService",
	"CreationDBService",
	"CreatorStoreService",
	"CrossDMScriptChangeListener",
	"DataStoreService",
	"Debris",
	"DebugSettings",
	"DebuggablePluginWatcher",
	"DebuggerConnectionManager",
	"DebuggerManager",
	"DebuggerUIService",
	"DeferredAssetManagerService",
	"DesignFoundationsService",
	"DeviceDisplayService",
	"DeviceIdService",
	"DraftsService",
	"DraggerService",
	"EditableService",
	"EditorSourceService",
	"EncodingService",
	"EventIngestService",
	"ExampleV2Service",
	"ExperienceAuthService",
	"ExperienceNotificationService",
	"ExperienceService",
	"ExperienceStateCaptureService",
	"ExperienceStateRecordingService",
	"ExplorerServiceVisibilityService",
	"ExternalIdentityService",
	"FaceAnimatorService",
	"FacialAgeEstimationService",
	"FacialAnimationRecordingService",
	"FacialAnimationStreamingServiceV2",
	"FeatureRestrictionManager",
	"FileManagerService",
	"FileSyncReplicationService",
	"FlagStandService",
	"FlyweightService",
	"FriendService",
	"FriendsCallingService",
	"GamePassService",
	"GameSettings",
	"GamepadService",
	"GenerationService",
	"GenericChallengeService",
	"Geometry",
	"GeometryService",
	"GongService",
	"GroupService",
	"GuiService",
	"GuidRegistryService",
	"HSRDataContentProvider",
	"HapticService",
	"HarmonyService",
	"HeapProfilerService",
	"HeatmapQueryService",
	"HeatmapService",
	"HeightmapImporterService",
	"HiddenPlayerService",
	"Hopper",
	"HttpRbxApiService",
	"HttpService",
	"ILegacyStudioBridge",
	"IXPService",
	"ImageScreenCaptureService",
	"IncrementalPatchBuilder",
	"InputReplayService",
	"InsertService",
	"InstanceExtensionsService",
	"InstanceFileSyncService",
	"InstanceRegistryService",
	"IntentService",
	"InternalMessagingService",
	"InternalMessagingServiceVerifier",
	"JointsService",
	"KeyboardService",
	"KeyframeSequenceProvider",
	"LanguageService",
	"LegacyStudioBridge",
	"Lighting",
	"LinkingService",
	"LiveScriptingService",
	"LiveSyncService",
	"LocalStorageService",
	"LocalizationService",
	"LodDataService",
	"LogReporterService",
	"LogService",
	"LoginService",
	"LuaSettings",
	"LuaWebService",
	"LuauExpressionService",
	"LuauScriptAnalyzerService",
	"MLModelDeliveryService",
	"MLService",
	"MarketplaceService",
	"MatchmakingService",
	"MaterialGenerationService",
	"MaterialService",
	"MemStorageService",
	"MemoryStoreService",
	"MeshContentProvider",
	"MessageBusService",
	"MessagingService",
	"MetaBreakpointManager",
	"MicroProfilerService",
	"ModerationService",
	"MomentsService",
	"MouseService",
	"NetworkClient",
	"NetworkServer",
	"NetworkSettings",
	"NonReplicatedCSGDictionaryService",
	"NotificationService",
	"OmniRecommendationsService",
	"OpenCloudService",
	"PackageService",
	"PackageUIService",
	"Packages",
	"PartyEmulatorService",
	"PatchBundlerFileWatch",
	"PathfindingService",
	"PerformanceControlService",
	"PermissionsService",
	"PhysicsService",
	"PhysicsSettings",
	"PinShortcutService",
	"PlaceAssetIdsService",
	"PlaceStatsService",
	"PlacesService",
	"PlatformCloudStorageService",
	"PlatformFriendsService",
	"PlatformLibraries",
	"PlayerDataService",
	"PlayerEmulatorService",
	"PlayerHydrationService",
	"PlayerViewService",
	"Players",
	"PluginConnectionService",
	"PluginDebugService",
	"PluginGuiService",
	"PluginManagementService",
	"PluginPolicyService",
	"PointsService",
	"PolicyService",
	"PopLatencyService",
	"Preloaded",
	"ProceduralBehaviorSchedulerService",
	"ProcessInstancePhysicsService",
	"ProjectService",
	"ProximityPromptService",
	"PublishService",
	"QueueService",
	"RbxAnalyticsService",
	"RecommendationService",
	"ReflectionService",
	"RemoteCommandService",
	"RemoteCursorService",
	"RemoteDebuggerServer",
	"RenderSettings",
	"ReplicatedFirst",
	"ReplicatedStorage",
	"RequestOrchestratorService",
	"RibbonNotificationService",
	"RobloxPluginGuiService",
	"RobloxReplicatedStorage",
	"RobloxServerStorage",
	"RolloutValidationService",
	"RomarkRbxAnalyticsService",
	"RomarkService",
	"RtMessagingService",
	"RunService",
	"RuntimeContentService",
	"RuntimeScriptService",
	"SafetyService",
	"SceneAnalysisService",
	"ScriptChangeService",
	"ScriptCloneWatcher",
	"ScriptCloneWatcherHelper",
	"ScriptCommitService",
	"ScriptContext",
	"ScriptDebuggerService",
	"ScriptEditorService",
	"ScriptProfilerService",
	"ScriptRegistrationService",
	"ScriptScannerService",
	"ScriptService",
	"Selection",
	"SelectionHighlightManager",
	"SerializationService",
	"ServerScriptService",
	"ServerStorage",
	"ServiceProvider",
	"ServiceVisibilityService",
	"SessionCheckService",
	"SessionService",
	"SharedTableRegistry",
	"SlimAnimationReplicationService",
	"SlimContentProvider",
	"SlimDebugSettings",
	"SlimReplicationService",
	"SlimService",
	"SmoothVoxelsUpgraderService",
	"SocialService",
	"SolidModelContentProvider",
	"SoundService",
	"SoundShimService",
	"SpawnerService",
	"StartPageService",
	"StarterGui",
	"StarterPack",
	"StarterPlayer",
	"StartupMessageService",
	"Stats",
	"StopWatchReporter",
	"Studio",
	"StudioAssetService",
	"StudioCameraService",
	"StudioCaptureService",
	"StudioData",
	"StudioDeviceEmulatorService",
	"StudioDeviceSimulatorService",
	"StudioPublishService",
	"StudioScriptDebugEventListener",
	"StudioSdkService",
	"StudioService",
	"StudioTestService",
	"StudioUserService",
	"StudioWidgetsService",
	"StylingService",
	"SystemThemeService",
	"TaskScheduler",
	"TeamCreateData",
	"TeamCreatePublishService",
	"TeamCreateService",
	"Teams",
	"TelemetryService",
	"TeleportService",
	"TemporaryCageMeshProvider",
	"TemporaryScriptService",
	"TestCoordinatorService",
	"TestService",
	"TextBoxService",
	"TextChatService",
	"TextService",
	"TextureGenerationService",
	"ThirdPartyUserService",
	"TimerService",
	"ToastNotificationService",
	"TouchInputService",
	"TraceRouteService",
	"TracerService",
	"TutorialService",
	"TweenService",
	"UGCAvatarService",
	"UGCValidationService",
	"UIDragDetectorService",
	"UniqueIdLookupService",
	"UnvalidatedAssetService",
	"UserGameSettings",
	"UserInputService",
	"UserService",
	"UserStorageService",
	"VRService",
	"VRStatusService",
	"VersionControlService",
	"VideoCaptureService",
	"VideoScreenCaptureService",
	"VideoService",
	"VirtualInputManager",
	"VirtualUser",
	"VisibilityCheckDispatcher",
	"Visit",
	"VisualizationModeService",
	"VoiceChatInternal",
	"VoiceChatService",
	"WebSocketService",
	"WebViewService",
	"WindowProtocolService",
	"Workspace",
	"WrapContentProvider",
	"WrapDeformMeshProvider",
}

-- Full API Dump method/event names (3671)
local ALL_API_METHODS = {}
do
	local s = [[Abort AcquireContextFocus AcquireFocus AcquireProofAsync AcquireWakeLock ActionEnabled ActionTaken Activate Activated ActiveUserSignedOut AdTeleportEnded AdTeleportInitiated Add AddAccessory AddAction AddAnimatedImageClipAsync AddAsync AddBone AddBoolField AddBreakpoint AddCFrameField AddCenterDialog AddColor AddConstraintFunction AddCoreScriptLocal AddCustomStatus AddDebugger AddEmote AddFace AddFocusCallback AddGlobalPointsField AddGlobalPointsTag AddInputPin AddInstanceField AddIntField AddItem AddKey AddKeyframe AddLine AddLines AddMarker AddMenu AddNewAction AddNewPlace AddNormal AddNumberField AddPath AddPersistentPlayer AddPlayers AddPose AddReadOnlyReasonsAsync AddReplicationFocus AddReplicationFocusPosition AddSelectionParent AddSelectionTuple AddSeparator AddSpecialKey AddStatus AddSubPose AddTag AddText AddToBlockList AddTriangle AddUV AddUnitVector3Field AddUserAsync AddVector2Field AddVector3Field AddVertex AddWatch AdjustSpeed AdjustWeight AdvanceToNextPageAsync AllNotificationsReadFromRibbon AllowedGearTypeChanged AncestryChanged AngularAccelerationToTorque AnimationIdSelected AnimationPlayed AnimationPlayedCoreScript AnimationStreamTrackPlayed AnnotationAdded AnnotationDeleted AnnotationEdited AnnotationResolved AnswerIncomingCall AppendTempAssetId AppendVantagePoint ApplyAngularImpulse ApplyAvatarRules ApplyAvatarRulesAsync ApplyDescription ApplyDescriptionAsync ApplyDescriptionFinished ApplyDescriptionReset ApplyDescriptionResetAsync ApplyFillInBox ApplyHighlight ApplyImpulse ApplyImpulseAtPosition ApplyJointVelocities ApplyLayout ApplyMesh ApplyPreset ApplyRecommendedStreamingSettings ApplyShadows ApplySpecificImpulse ApplySpotlight ApplyToDataModel ApplyTransform ApplyTransformSubregion ApproveAssetId ApproveAssetVersionId ArchiveBranchAsync AreInstanceTreesEquivalent ArePartsTouchingOthers Assert AssertLegacy AssetFetchFailed AssetImported AssetImportedSignal AttachCallout AttributeChanged AudioDeviceInputAdded AudioInputRequested AudioInstanceAdded AudioMetadataFailedResponse AudioMetadataRequest AudioMetadataResponse AuthCookieCopiedToEngine AutoRig AutoSelectGui AutoSetupAvatarAsync AutoSetupSerializedAvatarAsync AutoTranslateWillRun AutowedgeCell AutowedgeCells AvatarAssetModerationCompleted AvatarModerationCompleted AvatarOutfitModerationCompleted AwaitAllAsync AwaitAnyAsync AwaitSignalAsync AwardBadge AwardBadgeAsync AwardPoints AxisChanged AxisRotate BadgeAwarded BanAsync BarrierAsync Base64Decode Base64Encode BatchAdd BatchCommitAsync BatchCreated BatchExhausted BatchGetAsync BatchGetFaceAttributes BatchGetValues BatchGetVertexAttributes BatchGetVertexFaceAttributes BatchRemove BatchResponseReceived BatchRetrying BatchSent BatchSetFaceAttributes BatchSetValues BatchSetVertexFaceAttributes BeginDrag BeginRecording BeginSearch BenefitStatusReceived Bind BindAction BindActionAtPriority BindActionToInputTypes BindActivate BindAndFire BindButton BindCoreAction BindCoreActionAtPriority BindCoreActivate BindReceiptHandler BindReviewableContentEventProcessor BindToAnimation BindToClose BindToCollisionSummaries BindToMessage BindToMessageParallel BindToRenderStep BindToSimulation BindViolationProcessor Block BlockListChanged Blockcast Blocked BoundActionAdded BoundActionChanged BoundActionRemoved BreakJoints BreakpointAdded BreakpointChanged BreakpointRemoved BroadcastNotification BrowserWindowClosed BrowserWindowWillNavigate BubbleChatSettingsChanged BubbleDisplayed BugReportRequested BuildRigFromAttachments BulkImportFinished BulkImportStarted BulkMoveTo BustAvatarFetchCache Button1Down Button1Up Button2Down Button2Up ButtonChanged CacheCurrentTerrain CacheDefaults CacheHit CacheItemAdded CachePartOperationsAsync CalculateAverageEditableCageMeshDistance CalculateBodyMaxCageDistance CalculateConstraintsToPreserve CalculateEditableMeshInsideMeshPercentage CalculateEditableMeshModifiedCageBoundingBox CalculateEditableMeshNumModifiedCageUVsInSet CalculateEditableMeshTotalSurfaceArea CalculateEditableMeshUniqueUVCount CalculateJumpDistance CalculateJumpHeight CalculateJumpPower Call CallFunction CallInviteStateChanged CanCaptureScreenshot CanCaptureVideo CanCollideWith CanEditAssetAsync CanEnterCaptureMode CanHaveConnectionType CanLeaveTest CanLoadAsset CanPerformBinaryUpdate CanPromptOptInAsync CanRecordAsync CanSendCallInviteAsync CanSendGameInviteAsync CanSetNetworkOwnership CanSmoothVoxelsBeUpgraded CanUserChatAsync CanUsersChatAsync CanUsersDirectChatAsync CanUsersTransferRobuxAsync CanUsersWhisperAsync CanViewBrandProjectAsync Cancel CancelActiveOperation CancelAllNotification CancelAutoSetupAvatarAsync CancelGenerationRequest CancelImportHeightmap CancelNotification CancelPrefetch CaptureBegan CaptureController CaptureEnded CaptureFocus CaptureObjectSavedInternal CapturePluginGui CapturePluginGuiByPluginGuiIdAsync CaptureSaved CaptureSavedInternal CaptureScreenshot CaptureScreenshotAsync CaptureSnapshotAsync CellCenterToWorld CellCornerToWorld ChallengeAbandonedEvent ChallengeCompletedEvent ChallengeInvalidatedEvent ChallengeLoadedEvent ChallengeRequiredEvent ChangeState Changed CharacterAdded CharacterAppearanceLoaded CharacterRemoving Chat ChatActionReceived ChatIsLoaded ChatLocal Chatted Check CheckApplyDefaultClothing CheckApplyDefaultClothingAsync CheckEditableMeshInCameraFrustum CheckForUpdate CheckMomentTextStatusAsync CheckOcclusionAsync CheckOrRequestCameraPermission CheckUploadCaptureStatusAsync CheckUploadCaptureStatusForSupportTicketAsync CheckUserBadgesAsync Checkpoint ChildAdded ChildRemoved Clear ClearAllChildren ClearAsync ClearBreakpoints ClearCache ClearCachedAvatarAppearance ClearCachedTerrain ClearCharacterAppearance ClearComputerCameraMovementModes ClearComputerMovementModes ClearCreatorLayers ClearDefaults ClearError ClearInertialScrolling ClearJoinAfterMoveJoints ClearMockInput ClearOutput ClearProductInfoCaches ClearSessionId ClearTerrainSelectionHack ClearTestingValue ClearTokens ClearTouchCameraMovementModes ClearTouchMovementModes ClearUploadNames ClearUriScript ClearUserLayers ClearVoxelsAsync_beta Click ClickButton1 ClickButton2 ClientLuaDialogRequested ClientPurchaseSuccess ClientRequestData ClientRequestDataAsync ClientStart ClientStop Climbing Clone Close CloseAfterPublish CloseAsync CloseBrowserWindow CloseGameIfUserDoesntHavePerms CloseInspectMenu CloseInspectMenuRequest CloseLate CloseStatsBasedOnInputString CloseWindow Closed CloudEditSelectionChanged ClusterCompositionFinished CollaboratorIdleUpdate CollaboratorInstanceCreatedSignal CollaboratorInstanceDestroyedSignal CollaboratorStatusUpdatedSignal CollisionGroupContainsPart CollisionGroupSetCollidable CollisionGroupsAreCollidable ColormapHasUnknownPixels CommitBlock CommitEdits CommitStatusChanged CompleteMerge Completed ComposeDecalAsync CompressBuffer CompressLuaApp ComputeAsync ComputeBufferHash ComputeOriginalSizeForPart ComputeR15BodyBoundingBox ComputeRawPathAsync ComputeSmoothPathAsync ComputeStringHash ComputerCameraMovementModeRegistered ComputerMovementModeRegistered ConfigurationChanged ConformToAvatarRules ConformToAvatarRulesAsync ConnectAsync ConnectLocal Connected ConnectionAccepted ConnectionEnded ConnectionFailed ConnectionStarted ConsumePendingExperienceLeaveWithReason ControlPointChanged ConvertSlimAcrToObj ConvertToMockPackage ConvertToPackageAsync ConvertToPackageClosedCallback ConvertToPackageUpload ConvertToSmooth CopyAuthCookieFromBrowserToEngine CopyRegion CopyToClipboard CoreGuiChangedSignal CoreGuiRenderOverflowed CoreMessageReceived CountCells CountChildren Create CreateAdRewardFromDevProductId CreateAlias CreateAndSavePropertySet CreateAnimationByUploadingVideo CreateAnnotation CreateAssetAndWaitForAssetId CreateAssetAsync CreateAssetOrAssetVersionAndPollAssetWithTelemetryAsync CreateAssetOrAssetVersionAndPollAssetWithTelemetryAsyncWithAddParam CreateAssetOrAssetVersionAndPollAssetWithTelemetryAsyncWithAddParamErrorJson CreateAssetVersionAsync CreateBasicMeshPart CreateBranchAsync CreateButton CreateCageMeshPartsWithScaleForExportAsync CreateCallAsync CreateClient CreateCollection CreateCollisionGroup CreateDataModelContentAsync CreateDecalAsync CreateDeviceAsync CreateDockWidgetPluginGui CreateDockWidgetPluginGuiAsync CreateEditableImage CreateEditableImageAsync CreateEditableImageFromBinaryStringRobloxOnly CreateEditableImageFromDownloadAsync CreateEditableImageOriginalSizeAsync CreateEditableMesh CreateEditableMeshAsync CreateEditableMeshFromBinaryStringRobloxOnly CreateExpression CreateExtraAssetsFileFromPropertySet CreateFolder CreateHumanoidModelFromDescription CreateHumanoidModelFromDescriptionAsync CreateHumanoidModelFromUserId CreateHumanoidModelFromUserIdAsync CreateInternalDlic CreateJob CreateJoinAfterMoveJoints CreateLocalPlayer CreateMeshPartAsync CreateModel CreateNewParty CreateOrUpdateChannelPreferenceAsync CreateOrUpdatePlacePreference CreateOrUpdatePlacePreferenceAsync CreatePartGroup CreatePath CreatePlaceAsync CreatePlaceInPlayerInventoryAsync CreatePlugin CreatePluginAction CreatePluginMenu CreatePopupButton CreatePostAsync CreatePresetFromData CreateQWidgetPluginGui CreateReviewableContentAsync CreateReviewableContentKey CreateSessionAsync CreateSurfaceAppearanceAsync CreateTextContentAsync CreateTextureAsync CreateTextureInCageSpaceAsync CreateTextureInTargetSpaceAsync CreateThumbnailPlayer CreateToolbar CreateUserNotificationAsync CreateVideoSamplerAsync CreateVirtualInput CreateVoxelBuffer_beta CreateWebStreamClient CreateWebStreamClientInternal CurrentDataModelTypeAboutToChange CurrentDataModelTypeChanged CurrentDeviceIdChanged CustomStatusAdded CustomStatusRemoved DEPRECATED_SerializeInstances DEPRECATED_TrackEvent DEPRECATED_TrackEventWithArgs DataChanged DataModelSessionEnded DataModelSessionStarted Deactivate Deactivated Deactivation DebugClearDetachedPlaybacks DebugCounterGet DebuggerAdded DebuggerRemoved DecodeAvatarMovementProto DecompressBuffer DefaultLoadingGuiRemoved DefineCallout DefineFastFlag DefineFastInt DefineFastString DeleteAlias DeleteAnnotation DeleteCapture DeleteCapturesAsync DeleteParty DeleteVideoCapture DeleteVideoCaptureAsync DeregisterAutocompleteCallback DeregisterScriptAnalysisCallback DeriveNewMessageProperties DescendantAdded DescendantRemoving Deselected DeserializeAvatarModel DeserializeInstance DeserializeInstancesAsync DeserializeJSON Destroy Destroying DetachCalloutsByDefinitionId DetectDlic DetectUrl DeviceAccelerationChanged DeviceAccessTokenAvailable DeviceGravityChanged DeviceIntegrityAvailable DeviceListChanged DeviceRotationChanged DevicesChanged DialogChoiceSelected DidEnd DidLoop Died Disable DisableGamepadCursor Discard DiscardEdits Disconnect DisconnectAsync Disconnected DismissNotification DisplayBubble DisplaySystemMessage DistanceFromCharacter DoesMeshHaveSkinningData DoesSurfaceAppearanceMatchTexturePackAsync Done DownloadJobResult DraftAdded DraftRemoved DraftStatusChanged DragBegin DragContinue DragEnd DragEnter DragStart DragStopped DrawBufferAsync DrawCircle DrawImage DrawImageProjected DrawImageTransformed DrawLine DrawRectangle DrawTriangle DropdownClick Dump DumpToFileAsync EditAnnotation EditBreakpoint EditSourceAsyncWithRanges EditTextAsync EditWatch EditorsListChanged EffectivePathsChanged Emit EmitHybridEvent EmoteTriggered EmotesChanged EmotesLoaded EmotesMenuOpenChanged EmulatePCDeviceWithResolution EnableCoverage EnableDebugging EnableDetachedPlaybackMetadata EnableGamepadCursor EnableVoice EncounteredBreak EncryptStringForPlayerId EndCall EndDrag EndRecording EndRemoteRomarkTest EndTest Ended EquipTool Equipped EquippedEmotesChanged Error ErrorDetailed ErrorMessageChanged Evaluate EvaluateAsync EvaluateWatch Event EventConnected EventDisconnected ExecuteActionButton ExecuteCommand ExecuteCommandAsync ExecuteCrossExperienceCall ExecuteJavaScript ExecuteLuau ExecuteMultiplayerTestAsync ExecutePlayModeAsync ExecuteRunModeAsync ExecuteScript Exists ExitPlayback ExpChatFeatureValueChanged ExperimentalSolverIsEnabled ExportInstanceToGlbAsync ExportMeshToGlbAsync ExportPlace ExportSelection ExpressionAdded ExpressionsCleared Fail Failed FallingDown FastForward FeatureTimeoutAttempt FeatureTimeoutRestored FetchAssetQualitySummaryFromGltfAsync FetchAssetQualitySummaryFromJobIdAsync FetchAssetQualitySummaryFromJobIdV2Async FetchAssetQualitySummaryFromUrlAsync FetchAssetQualityValidationEntriesFromModelsAsync FetchAssetQualityValidationRawFromModelsAsync FetchAssetQualityVisualizationDataFromUrlAsync FetchAssetWithFormat FetchExtraAssets FetchPostAsync FetchReceipt FetchTestControlsAsync FillBall FillBallSlot FillBlock FillBlockSlot FillCylinder FillCylinderSlot FillRegion FillRegionSlot FillWedge FillWedgeSlot FilterAndTranslateStringAsync FilterStringAsync FilterStringForBroadcast FilterStringForPlayerAsync FindClosestPointOnSurface FindClosestVertex FindFirstAncestor FindFirstAncestorOfClass FindFirstAncestorWhichIsA FindFirstChild FindFirstChildOfClass FindFirstChildWhichIsA FindFirstDescendant FindPartOnParabola FindPartOnRay FindPartOnRayWithIgnoreList FindPartOnRayWithWhitelist FindPartsInRegion3 FindPartsInRegion3WithIgnoreList FindPartsInRegion3WithWhiteList FindPathAsync FindScriptDocument FindService FindVerticesWithinSphere FinishFullLoading FinishRecording FinishSpan FinishTask FinishedReplicating Fire FireActionButtonFoundSignal FireAllClients FireClient FireCustomEvent FireEvent FireInGameEconomyEvent FireLogEvent FireOnUGCSubmitCompleted FirePlayerProgressionEvent FireServer FirstPersonTransition FlagCaptured Flush Flushed FocusChanged FocusConnection FocusLost FocusStateChanged Focused ForceGeneration ForceReloadSource ForceSetSelectionAsync ForceTenFootInterface FormatByKey ForwardAsync FragmentAsync FreeFalling FriendRequestEvent FriendStatusChanged FriendsUpdated FromHeightmapAsync FullProcess FullscreenChanged GameInvitePromptClosed GameNameUpdated GamePassFreeTrialRedeemed GamePublishCancelled GamePublishFinished GameStreamingEnabled GameStreamingResolutionReady GamepadConnected GamepadDisconnected GamepadSupports GamepadThumbstick1Changed GenerateAnimationAsync GenerateAssetQualityGltfFromInstanceAsync GenerateAvatar2DPreviewAsync GenerateAvatarAsync GenerateFragmentSites GenerateGUID GenerateItemListAsync GenerateMaterialVariantsAsync GenerateMeshAsync GenerateModelAsync GenerateMomentTextAsync GenerateSessionInfoString GenerateTextAsync GenerateTexture GenerateWaterFlowMap GenerationNotificationSignal Get GetAbsolutePosition GetAccessories GetAccessoryHandleScale GetAccessoryType GetActionButtonEvent GetActive GetActor GetActual GetAdAvailabilityNowAsync GetAdAvailabilityNowForUniverseAsync GetAdTeleportInfo GetAdjacentFaces GetAdjacentVertices GetAllBoundActionInfo GetAllBoundCoreActionInfo GetAllInstances GetAllPresets GetAllTags GetAlliesAsync GetAndClearCallFailureMessage GetAndClearLastPendingUrl GetAngleAttenuation GetAnglesAtTime GetAnimatedImageClipFramesAsync GetAnimatedImageClipsChangedSignal GetAnimationClip GetAnimationClipAsync GetAnimationClipById GetAnimationMemoryAsync GetAnimationNodeDefinition GetAnimationNodeTypes GetAnimationValueNodeDefinition GetAnimationValueNodeTypes GetAnimations GetAnimationsAsync GetAnnotationThreads GetApiV1 GetAppAgeSignalsAsync GetAppliedDescription GetAppliedInstance GetAppliedStyles GetArg GetArrivingTeleportGui GetAssetFetchStatus GetAssetFetchStatusChangedSignal GetAssetIdsForPackage GetAssetIdsForPackageAsync GetAssetInfoAsync GetAsync GetAsyncFullUrl GetAttachedReceivers GetAttribute GetAttributeChangedSignal GetAttributeNames GetAttributes GetAudibilityFor GetAudioApiByDefault GetAudioInstances GetAudioMemoryAsync GetAudioMetadataAsync GetAudioProcessingSettings GetAutoUIScaleHundredths GetAutocompleter GetAvailableConnection GetAvailableSubscriptionProductsAsync GetAvailableThemes GetAvailableTintModes GetAvatarRules GetAvatarRulesAsync GetAwakeContactNormals GetAwakeContactParts GetAwakeContactPositions GetAwakeRootParts GetAwardablePoints GetAxis GetBadgeConfigureUrl GetBadgeInfoAsync GetBadgeUploadUrl GetBanHistoryAsync GetBaseCategories GetBaseMaterialOverride GetBaseSets GetBatchItemDetails GetBatchItemDetailsAsync GetBatchTokenDetailsAsync GetBatchWindowDelayMax GetBatchWindowDelayMin GetBinaryContents GetBlock GetBlockListInitialized GetBodyPartR15 GetBoneByName GetBoneCFrame GetBoneIsVirtual GetBoneName GetBoneParent GetBones GetBoundActionInfo GetBoundCoreActionInfo GetBoundingBox GetBoundingBoxManipulationData GetBoundingRect GetBranchesAsync GetBreadcrumbs GetBreakpointById GetBreakpoints GetBrickCount GetBrowserTrackerId GetBrowserTrackerLayerLoadingStatus GetBrowserTrackerLayerVariables GetBrowserTrackerStatusForLayer GetBuffer GetBundleDetailsAsync GetBundlesByAssetIdAsync GetButton GetCageOffset GetCallingState GetCameraDevices GetCameraState GetCameraYInvertValue GetCampaignEligibilityAsync GetCanManageAsync GetCanRedo GetCanUndo GetCapabilitiesAsync GetCapabilitiesUsedInPackageAsync GetCaptureFilePathAsync GetCaptureSizeAsync GetCaptureStorageSizeAsync GetCaptureUploadDataAsync GetCell GetCenter GetChainCount GetChainLength GetChangeType GetChangedState GetChannelId GetChannelPreferenceAsync GetCharacterAppearanceAsync GetCharacterAppearanceInfoAsync GetChatForUserAsync GetChatGroupsAsync GetChatableUserCountAsync GetChildren GetClass GetClassIcon GetClasses GetClientFeaturesAsync GetClientId GetClipEvaluatorAsync GetClosestDialogToPosition GetClosestPointOnSurface GetClosestVisibleDialogToPosition GetCollaboratorsList GetCollection GetCollections GetCollisionGroupId GetCollisionGroupName GetCollisionGroups GetColor GetColorAlpha GetColors GetCommerceProductInfoAsync GetComponentCurves GetCondition GetConditions GetConfigAsync GetConfigForPlayerAsync GetConnectedGamepads GetConnectedParts GetConnectedWires GetConnectionById GetConstraints GetContainedJointLabels GetContentMapMemoryBytes GetContentMemoryData GetContents GetContext GetContextBreakpoints GetControlAndVariantRolloutFlags GetControlPoint GetControlPoints GetCore GetCoreGuiEnabled GetCoreScriptVersion GetCorescriptLocalizations GetCountryRegionForPlayerAsync GetCoverageStats GetCreatedTimestampUtcMs GetCreatorAssetID GetCreatorLayerLoadingStatus GetCreatorLayerVariables GetCreatorStatusForLayer GetCreatorStoreProductInfoAsync GetCredentialsHeaders GetCurrentDeviceId GetCurrentLocalToolIcon GetCurrentOrientation GetCurrentPage GetCurrentPlaybackRestartFrames GetCurrentPlayers GetCurrentState GetCurrentValue GetData GetDataInRange GetDataSize GetDataStore GetDebugAppliedForce GetDebugAppliedTorque GetDebugData GetDebugId GetDebuggers GetDecompressedBufferSize GetDefaultFramerateCap GetDefaultPropertyTransition GetDefaultValue GetDeformedCFrameAsync GetDependencyContentIds GetDerives GetDescendants GetDetachedPlaybackData GetDetailedFailedRequests GetDeveloperProductsAsync GetDeviceAcceleration GetDeviceAccessToken GetDeviceAsync GetDeviceCameraCFrame GetDeviceCameraCFrameForSelfView GetDeviceGravity GetDeviceId GetDeviceInfo GetDeviceInfoAsync GetDeviceIntegrityToken GetDeviceIntegrityTokenYield GetDeviceLevel GetDeviceListAsync GetDeviceRotation GetDeviceType GetDiffAsync GetDistanceAttenuation GetDistributedCounter GetDocumentationUrl GetDraftStatus GetDrafts GetDurationLoggerTimestamp GetDynamicHeadEditableMeshInactiveControls GetEditableCagingRelevancyMetrics GetEditableImageSize GetEditableMeshMaxNearbyVerticesCollisions GetEditableMeshSkinningTransferJointsInfo GetEditableMeshTriCount GetEditableMeshVertColors GetEditableMeshVerticesSimilarityRate GetEditableMeshVerts GetEditorSource GetEditors GetEffectiveUIScaleHundredths GetEmotes GetEmotesMenuOpen GetEmulatedPartyAsync GetEmulatedPartyConfiguration GetEmulatedPolicyInfo GetEnemiesAsync GetEngineFeature GetEntries GetEquippedEmotes GetErrorCode GetErrorDetails GetErrorMessage GetErrorType GetErrors GetEventRsvpStatusAsync GetEventsOfClass GetExecutingPlayer GetExpected GetExpectedTposeRotation GetExperienceEventAsync GetExtentsSize GetFFlag GetFFlagOverrides GetFFlags GetFVariable GetFaceColors GetFaceNormals GetFaceUVs GetFaceVertices GetFaces GetFacesWithAttribute GetFacesWithColor GetFacesWithNormal GetFacesWithUV GetFacsCorrectivePose GetFacsCorrectivePoses GetFacsDrivenJointNamesFromEditableMesh GetFacsPose GetFacsPoses GetFailedRequests GetFailures GetFamilyInfoAsync GetFastFlag GetFastInt GetFastString GetFavorite GetFavoriteAsync GetFilename GetFilesInDirAsync GetFingerControl GetFingerTip GetFocusedContextId GetFocusedTextBox GetFollowUserId GetFontMemoryData GetForcedPop GetFrame GetFrameById GetFreeDecals GetFreeDecalsAsync GetFreeModels GetFreeModelsAsync GetFriendStatus GetFriendsAsync GetFriendsInServerAsync GetFriendsInUniverseAsync GetFriendsOnline GetFriendsOnlineAsync GetFriendsWhoPlayedAsync GetFullName GetGainAt GetGamePlacesAsync GetGamePointBalance GetGameSessionID GetGamepadConnected GetGamepadCursorPosition GetGamepadState GetGameplayPausedNotificationEnabled GetGlobalDataStore GetGlobalUserId GetGlobals GetGroupId GetGroupInfoAsync GetGroupsAsync GetGuiInset GetGuiIsVisible GetGuiObjectsAtPosition GetGuiObjectsInCircle GetHardwareSafeViewport GetHarmonyQualityLevel GetHash GetHashMap GetHeadShapesAsync GetHeightmapPreviewAsync GetHistory GetHttpEnabled GetHttpResultHistory GetHumanoidDescriptionFromOutfitId GetHumanoidDescriptionFromOutfitIdAsync GetHumanoidDescriptionFromUserId GetHumanoidDescriptionFromUserIdAsync GetIdentities GetIdentity GetImageForKeyCode GetImportTree GetInputActions GetInputBindings GetInputContexts GetInputDevice GetInputDevices GetInputPins GetInputSchemaKeyCodeTree GetInsetArea GetInspectMenuEnabled GetInstanceAddedSignal GetInstanceByRfc4122String GetInstanceCompositionAsync GetInstanceConflicts GetInstanceRemovedSignal GetInstances GetInteractingEmitters GetInteractingListeners GetInternalUri GetInventory GetInventoryAsync GetIsEmulationEnabled GetIsLoadingInternalTranslations GetIsMaterialActionAsToolEnabled GetIsThirdPartyAssetAllowed GetIsThirdPartyPurchaseAllowed GetIsThirdPartyTeleportAllowed GetItem GetItemDetails GetItemDetailsAsync GetJobStatus GetJobsInfo GetJoinData GetJoinMode GetJoint GetJointFromName GetJointLabels GetJointNames GetJointRangeMax GetJointRangeMin GetJointSize GetJoints GetKeyAtIndex GetKeyIndicesAtTime GetKeyframeSequence GetKeyframeSequenceAsync GetKeyframeSequenceById GetKeyframeSequences GetKeyframeSequencesForSelectedRestPose GetKeyframeSequencesForSelectedRestPoseWithClip GetKeyframes GetKeys GetKeysPressed GetLabels GetLargestCutoffDistance GetLast GetLastForce GetLastInputType GetLastLuaUrl GetLatestAssetVersionAsync GetLayeredClothingPostDeformationSize GetLayeredClothingPostDeformationSizeAsync GetLayoutNodeTree GetLength GetLexemes GetLimb GetLine GetLineCount GetListener GetListenerWorldCFrame GetLocalFileContents GetLocalPlayerTeleportData GetLocals GetLogHistory GetLogHistoryAsync GetLogPath GetLogger GetLogicalCaptionButtonsBounds GetLuauHeapInstanceReferenceReport GetLuauHeapMemoryReport GetMainViewSessionId GetMarkerAtIndex GetMarkerReachedSignal GetMarkers GetMass GetMaterialColor GetMaterialOverrideChanged GetMaterialSlot GetMaterialVariant GetMaxCollisionGroups GetMaxControlPoints GetMaxQualityLevel GetMaximalJointDistancesWithinFacs GetMemStats GetMemoryCategoryNames GetMemoryUsageMbAllCategories GetMemoryUsageMbAllCategoriesFiltered GetMemoryUsageMbFiltered GetMemoryUsageMbForTag GetMergeChanges GetMergeResolution GetMergeStatus GetMeshDataBinaryString GetMeshIdFromAliasName GetMeshIdFromAssetId GetMeshIdsHash GetMeshVerts GetMessage GetMessageId GetMetaDataAsync GetMetadata GetMethodsOfClass GetMicDevices GetMinAndMaxMeshSizeAcrossAllFacs GetMinutesAfterMidnight GetMixerTime GetModelCFrame GetModelSize GetMoonDirection GetMoonPhase GetMotor GetMouse GetMouseButtonsPressed GetMouseDelta GetMouseLocation GetMoveVelocity GetNameFromUserIdAsync GetNames GetNativeTitleBarControlsPosition GetNavigationGamepads GetNetworkOwner GetNetworkOwnershipAuto GetNetworkPing GetNoCollisionConstraints GetNodeLocalCFrame GetNodeWorldCFrame GetNonChatStringForBroadcastAsync GetNonChatStringForUserAsync GetNormal GetNormals GetNotificationTypeList GetNumAwakeParts GetOTAPluginVersion GetObjects GetObjectsAllOrNone GetObjectsAsync GetObjectsList GetOnboardingCompleted GetOpaqueContentMetadataMap GetOrCreateUniqueId GetOrCreateUniqueIdRemoteCommand GetOrderedDataStore GetOrderedInputPinNames GetOrientationAsync GetOrphanPathSubscribers GetOutfitDetails GetOutfitDetailsAsync GetOutfits GetOutfitsAsync GetOutputDevice GetOutputDevices GetOutputPins GetOverrideStatus GetOverrides GetPackageInfo GetPaginatedMemoryByTexture GetPanSpeed GetParameter GetParameterDefaults GetParents GetPartBoundsInBox GetPartBoundsInRadius GetPartGroup GetParticipants GetPartsInPart GetPartsObscuringTarget GetPartyAsync GetPartyMembers GetPassOwnershipAsync GetPasteText GetPathSubscribers GetPaths GetPeakLevel GetPendingJoinAttempt GetPermissions GetPersistentPlayers GetPhysicsCost GetPhysicsStepId GetPhysicsThrottling GetPioneerRootPlaceId GetPioneerSource GetPivot GetPixelDensityAsync GetPlaceJoinState GetPlacePreference GetPlacePreferenceAsync GetPlaceholderInstanceTree GetPlatform GetPlatformFriends GetPlaySessionId GetPlaybackCurrentFrame GetPlaybackMode GetPlaybackState GetPlayer GetPlayerByUserId GetPlayerFromCharacter GetPlayerPlaceInstanceAsync GetPlayerSegmentsAsync GetPlayers GetPlayersByPartyId GetPlayingAnimationTracks GetPlayingAnimationTracksCoreScript GetPluginComponent GetPluginConnectionsOfType GetPluginPolicy GetPointBalance GetPointCoordinates GetPolicyInfoForPlayerAsync GetPolicyInfoForServerRobloxOnlyAsync GetPoses GetPosition GetPositionOnCurve GetPositionOnCurveArcLength GetPostTransforms GetPreTransforms GetPredictionStatus GetPreferredBindingList GetPrefetchDownloadStatus GetPreinitPayload GetPreset GetPresetsAsync GetPreview GetPrimaryPartCFrame GetProductInfo GetProductInfoAsync GetProfileConfigurationFromUserIdAsync GetProperties GetPropertiesOfClass GetPropertiesResolved GetProperty GetPropertyChangedSignal GetPropertyNames GetPropertyResolved GetPropertyTransitions GetPropertyValue GetProtocolLaunchUpdateName GetProtocolLaunchUpdateType GetProtocolMethodRequestMessageId GetProtocolMethodResponseMessageId GetQueue GetQueuePosition GetQuotasAsync GetR15JointLabels GetR15JointNames GetR6JointLabels GetR6JointNames GetRangeAsync GetRankInGroup GetRankInGroupAsync GetRawFinalTarget GetRawScreenScale GetReadOnlyReasons GetRealPhysicsFPS GetReceivedUpdateSignal GetRecommendationItemAsync GetRecommendedAssets GetRecommendedAssetsAsync GetRecommendedBundles GetRecommendedBundlesAsync GetRecordAsync GetRecordConfig GetRecordingDevices GetReferenceFrame GetReferencePosition GetReferenceRotation GetRegionWireframe GetRegisteredCollisionGroups GetRegisteredComputerCameraMovementModes GetRegisteredComputerMovementModes GetRegisteredContexts GetRegisteredCreatorLayersToStatus GetRegisteredOrchestrators GetRegisteredTouchCameraMovementModes GetRegisteredTouchMovementModes GetRegisteredUserLayersToStatus GetRelativeMousePosition GetRelativeVelocityAtFloor GetRemoteBuildMode GetRenderCFrame GetReplicationWeight GetReportAdInfo GetRequestBudgetForRequestType GetRequests GetResolutionAsync GetResolutionScale GetResourceByCategory GetResponseDelayMax GetResponseDelayMin GetRigVisualization GetRobloxClientChannel GetRobloxClientIxpEnrolledExperiments GetRobloxGuiFocused GetRobloxSubscriptionDetailsAsync GetRobloxVersion GetRobuxBalance GetRoleInGroup GetRoleInGroupAsync GetRolesInGroupAsync GetRoll GetRootPart GetRootSID GetRootVariables GetRotationAtTime GetSafeZoneOffsets GetSampledInertialVelocity GetSamplesAtTimesAsync GetScale GetScalingModeAsync GetScheduledNotifications GetSchema GetScreenResolution GetScreenSpaceBounds GetScreenshotCaptureObject GetScript GetScriptDocuments GetScriptFilePath GetScriptMemoryAsync GetScrollVelocity GetSdk GetSearchResults GetSeatRequested GetSecondaryAxis GetSecret GetSegmentCount GetSelectedRibbonTool GetSelectedText GetSelection GetSelectionEnd GetSelectionHighlightsEnabled GetSelectionStart GetSerializedSizeExcludingCollisionAsync GetServerAttribute GetServerFeaturesAsync GetServerTimeNow GetService GetServiceVisibility GetSessionID GetSessionId GetSessionTag GetSetting GetSharedTable GetShouldUseLuaChat GetSingleReportAdInfo GetSize GetSizeAsync GetSizeInVoxels GetSkinnedJointNamesFromEditableMesh GetSmoothedFinalTarget GetSnapshot GetSortedAsync GetSortedMap GetSoundMemoryData GetSource GetSourceContainerByScriptGuid GetSpectrum GetStack GetStackTrace GetStandardQueue GetStartupAssetId GetStartupMessage GetStartupPluginId GetState GetStateEnabled GetStats GetStatus GetStatuses GetStoppingSignal GetString GetStringForKeyCode GetStringUniqueId GetStudioUserId GetStyleInfo GetStyleRules GetStyleSheetDerivesChain GetStyleSheetInfo GetStyled GetStyledPropertyChangedSignal GetStyledPropertyNames GetSubPoses GetSubscriptionProductInfoAsync GetSubscriptionPurchaseInfoAsync GetSuggestions GetSunDirection GetSupportedGamepadKeyCodes GetSurfaceSlotsAsync GetSyncState GetSyncedInstance GetSyncingCollaborators GetTableEntries GetTagAddedSignal GetTagRemovedSignal GetTagged GetTags GetTangentOnCurve GetTangentOnCurveArcLength GetTargetInstance GetTargetNames GetTeams GetTeleportData GetTeleportSetting GetTemporaryContent GetTemporaryId GetTermsOfUseUrl GetTerrainWireframe GetTestArgs GetTestControlSchema GetTestControls GetTestTags GetTests GetText GetTextBoundsAsync GetTextChannelWindows GetTextSize GetTextSizeOffsetAsync GetTextureIdFromAliasName GetTextureIdFromAssetId GetThirdPartyTeleportInfo GetThreadById GetThreads GetTiltSpeed GetTimeOfKeyframe GetTintMode GetTitleBarMode GetToolRequested GetTooltip GetTopbarTransparency GetTotalMemoryUsageMb GetTotalScriptPlusExecutionTime GetTouchingParts GetTouchpadMode GetTposeAdjustment GetTrackByAnimationId GetTrackerData GetTrackerLodController GetTransforms GetTranslationForLocale GetTranslations GetTranslator GetTranslatorForLocaleAsync GetTranslatorForPlayer GetTranslatorForPlayerAsync GetTriangleCompositionAsync GetTutorialState GetUV GetUVs GetUiMessage GetUnder13 GetUnderlyingAudioPlayer GetUniversalAppAdsEligibility GetUnparentedInstancesAsync GetUnrecordableInstancesAsync GetUpcomingExperienceEventsAsync GetUploadStatus GetUpvalues GetUri GetUserAgent GetUserBadgesAsync GetUserCFrame GetUserCFrameEnabled GetUserCategories GetUserDataAsync GetUserFromGlobalUserIdAsync GetUserId GetUserIdAccessList GetUserIdFromNameAsync GetUserIds GetUserInfosByUserIdsAsync GetUserLayerLoadingStatus GetUserLayerVariables GetUserPlatformName GetUserSets GetUserStatusForLayer GetUserSubscriptionDetailsAsync GetUserSubscriptionDetailsInternalAsync GetUserSubscriptionPaymentHistoryAsync GetUserSubscriptionStatusAsync GetUserThumbnailAsync GetUsersPriceLevelsAsync GetValidationRules GetValue GetValueAtTime GetValueChangedSignal GetValueString GetVariableById GetVariableByIndex GetVariableByName GetVariables GetVelocityAtPosition GetVersionAsync GetVersionAtTimeAsync GetVertexBoneWeights GetVertexBones GetVertexColors GetVertexFaceColor GetVertexFaceNormal GetVertexFaceUV GetVertexFaces GetVertexNormals GetVertexUVs GetVertices GetVerticesWithAttribute GetVerticesWithColor GetVerticesWithNormal GetVerticesWithUV GetVideoGenSessionAsync GetVideoGenTriggersAsync GetViewport GetVoiceChatApiVersion GetVoiceChatAvailable GetVoiceChatRestrictionStatus GetVoiceExperienceId GetWatchValue GetWatches GetWaterCell GetWaveformAsync GetWaypoints GetWidgetFromLabel GetWidgetFromPluginGui GetWindowState GetWithPlayerId GetWorldCFrame GettingUp GizmoRaycast GrantAchievement GraphicsQualityChangeRequest GridBackendReloadRequired GuiVisibilityChangedSignal GuidLineContentsChanged GuidNameChanged HandleGamepadAxisInput HandleGamepadButtonInput HandleGamepadConnect HandleGamepadDisconnect HandleLuaUIEvent HandleSelfieConsentResult HandleSelfieQRResult HandleWhyThisAdClicked HasAchieved HasAllocatedUniverseChatContext HasAnimation HasAppearanceLoaded HasBlockedPlayer HasCustomStatus HasDeviceWithId HasField HasInternalPermission HasItem HasMoreResults HasOverrideFACSData HasSelectedText HasStatus HasTag HasUserCompletedTutorial HashMeshAsync HaveActiveUser HealthChanged Heartbeat HideEudsaDisclosure HideNotification HideSelfView HideSpotlight HideWidgets Hit HttpGetAsync HttpPostAsync HttpRequestAsync HttpResultOut IKMoveTo IdDebugString Idle Idled IkSolve ImageImportedSignal ImportFBXAnimationFromFilePathUserMayChooseModel ImportFBXAnimationUserMayChooseModel ImportFbxAnimation ImportFbxAnimationAsync ImportFbxRig ImportFbxRigAsync ImportFbxRigWithoutSceneLoad ImportHeightmap ImportHeightmapWithMaterialSlotsAsync ImportLoadedFBXAnimation ImportSessionFinished ImportSessionStarted ImportVideoWithPrompt InExperienceBrowserRequested InFocusMode InFullScreen InStudioMode IncrementAsync IndicatorHidden IndicatorShown Info Init InitializeCreatorLayers InitializeRemoteAllowList InitializeServerAttributesForStudio InitializeUserLayers InputActionsChanged InputBegan InputBindingsChanged InputChanged InputContextsChanged InputEnded InputHoldBegin InputHoldEnd InputPinsChanged InputText InquiryAsync Insert InsertAsset InsertAudio InsertControlPoint InsertImage InsertImages InsertKey InsertKeyValue InsertMarkerAtTime InsertMesh InsertMeshesWithLocation InsertModel InsertObjectsAndJoinIfLegacyAsync InsertPackage InsertStyleRule InsertVideo InspectMenuEnabledChangedSignal InspectPlayerFromHumanoidDescription InspectPlayerFromHumanoidDescriptionRequest InspectPlayerFromUserId InspectPlayerFromUserIdWithCtx InspectPlayerFromUserIdWithCtxRequest InstancePassesFilter InstancePinned InstanceUnpinned InternalCheckPlayabilityAsync InternalFacsOverrideChanged InternalGenerateMeshAsync InternalGetStartPlaceIdAsync InternalRequestReviewableContentReviewAsync Interpolate InterpolateView InterpolationFinished Intersect IntersectAsync Invoke InvokeAsync InvokeChatCallback InvokeClient InvokeGameInvitePromptClosed InvokeIrisInvite InvokeIrisInvitePromptClosed InvokeOptInPromptClosed InvokeServer InvokeShareSheetClosed IsA IsAccountSwitchingSupported IsActivated IsActivatedWithExclusiveMouse IsAdLoaded IsAgeRestricted IsAncestorOf IsAudioEnabled IsAutocompleteCallbackRegistered IsAvailable IsAvatar IsBestFriendsWith IsCapturingVideo IsChatRestrictionSupported IsClient IsCollisionGroupRegistered IsCommandBar IsConnectionForPlayDataModel IsContentLoaded IsContextFocused IsContextVoiceEnabled IsCrossExperienceLaunchFeasible IsDefaultLoadingGuiRemoved IsDeformedLayeredClothingOutOfRenderBounds IsDescendantOf IsDidDetachSupported IsDisabled IsEdit IsEditableMeshNumCoplanarIntersectionsOverLimit IsEnabled IsFinishedReplicating IsFocused IsFriendsWith IsFriendsWithAsync IsGamepadButtonDown IsGearTypeAllowed IsGltf IsGrounded IsHSRReady IsInExperience IsInGroup IsInGroupAsync IsInviteFriendsEnabled IsKeyDown IsLegal IsLoaded IsLoadedFromProject IsLoadingInternalTranslationsSettingChanged IsMaquettes IsMaterialSlotInvalid IsMemoryTrackerEnabled IsModifierKeyDown IsMotorSupported IsMouseButtonPressed IsNavigationGamepad IsNetworkStateAvailable IsPioneerApp IsPlaceEnabled IsPluginInstalled IsPluginUpToDate IsPostProcessReady IsProfileEnabled IsPropertyModified IsProtectedChatEnabled IsPublishPaused IsPurchaseSimulated IsR15 IsReadOnly IsRecordingInProgress IsRegion3Empty IsRegion3EmptyWithIgnoreList IsResimulating IsRevealPinnedExperienceAvailable IsRunMode IsRunning IsScriptAnalysisCallbackRegistered IsServer IsServerEnabled IsSingleSignOnSupported IsStarted IsStreamedOut IsStudio IsSubscribePaused IsTeamCreateViewer IsTeamTest IsTenFootInterface IsThreadParent IsUniverseEnabled IsUniverseMetadataLoaded IsUrlRegistered IsUserDataAvailable IsUserFeatureEnabled IsVRAppBuild IsValidColormap IsValidHeightmap IsValidR15 IsValidR15Plus IsVerified IsVibrationSupported IsVideoEnabled IsVoiceEnabledForUserIdAsync IsWatchingScriptLine ItemAdded ItemChanged ItemRemoved ItemSelectedInCaptureMode ItemWasSet IterateVoxelsAsync_beta JSONDecode JSONDecodeAsync JSONEncode JSONEncodeAsync JavaScriptCallback JitterStarted JoinByGroupId JoinByGroupIdToken JoinToOutsiders JumpRequest JumpTo JumpToIndex Jumping KeyDown KeyPressed KeyUp KeyframeReached Kick LaserPointerTriggered LastInputTypeChanged Launch LaunchBulkImport LaunchExperience LaunchExperienceFromSource LaunchExperienceFromSourceWithCallback Leave LeaveExperienceWithReason LeaveTest LightingChanged ListDataStoresAsync ListEncryptedAssets ListFilesInFolderAsync ListItemsAsync ListKeysAsync ListPluginGuisAsync ListTests ListVersionsAsync Load LoadAnimation LoadAnimationCoreScript LoadAnnotationReplies LoadAnnotations LoadAsset LoadAssetAsync LoadAssetVersion LoadAssetWithBytecodeAsync LoadAssetWithFormat LoadAsync LoadAvatar2DPreviewAsync LoadBoolean LoadCharacter LoadCharacterAppearance LoadCharacterAsync LoadCharacterBlocking LoadCharacterWithAvatarRulesAsync LoadCharacterWithHumanoidDescription LoadCharacterWithHumanoidDescriptionAsync LoadData LoadFromHumanoid LoadFromModel LoadGeneratedAvatarAsync LoadGeneratedMeshAsync LoadInstance LoadLocalAsset LoadModelFromGlbAsync LoadModelFromUrlAsync LoadNumber LoadPackageAssetAsync LoadPlatformAsync LoadPlaybackAsync LoadPostProcessModelAsync LoadResolvedAnnotations LoadRigAndDetectType LoadStreamAnimation LoadStreamAnimationForSelfieView_deprecated LoadStreamAnimationV2 LoadString Loaded LocalGamesFromRegistryUpdatedSignal LocalIkSolve LocalPlayerArrivedFromTeleport LocalPlayerModerated LocalSimulationTouched LocalToolEquipped LocalToolUnequipped Log LogActionEvent LogBrowserTrackerLayerExposure LogCounter LogCreatorLayerExposure LogCustomEvent LogDurationEvent LogDurationEventWithTimestamp LogEconomyEvent LogEvent LogFlagLinkedUserLayerExposure LogFunnelStepEvent LogImpressionEvent LogJourneyEvent LogOnboardingFunnelStepEvent LogPreferenceEvent LogProgressionCompleteEvent LogProgressionEvent LogProgressionFailEvent LogProgressionStartEvent LogPublisherWebRTCStats LogStat LogSubscriptionWebRTCStats LogUserLayerExposure LoginFailed LoginSucceeded Logout Looped MagicLogin MagicLoginEvent MakeJoints MakeRequest MaterialFillToolEnabledChanged Maximize MenuClosed MenuOpened MenuTeleportAttempt MergeStateChanged MergeStateCleared MergeStatusChanged MergeVertices Message MessageOut MessageReceived MetaBreakpointAdded MetaBreakpointChanged MetaBreakpointRemoved MetaBreakpointSetChanged Minimize Misprediction MockViolationCallbackAsync ModifyVertices ModifyVoxelsAsync_beta MouseButton1Click MouseButton1Down MouseButton1Up MouseButton2Click MouseButton2Down MouseButton2Up MouseClick MouseDown MouseDrag MouseEnter MouseEnterStudioViewport MouseHoverEnter MouseHoverLeave MouseLeave MouseLeaveStudioViewport MouseMove MouseMoved MouseUp MouseWheelBackward MouseWheelForward Move MoveMouse MoveStateChanged MoveTo MoveToFinished MultiEditTextAsync MultiGetCanCollaborate MultiGetCanCollaborateRetrieved MutateWindow MutationFailed NativeClose NativePurchaseFinished NativePurchaseFinishedV2 NativePurchaseFinishedWithLocalPlayer NativePurchaseFinishedWithLocalPlayerV2 NavigationRequested Negate NetworkPausedEnabledChanged NewNotificationFromRibbon Next NoPromptApplyProfileConfiguration NoPromptCreateOutfit NoPromptDeleteOutfit NoPromptRenameOutfit NoPromptSaveAvatar NoPromptSaveAvatarThumbnailCustomization NoPromptSetFavorite NoPromptUpdateOutfit NormalizeAsync NotificationReadFromRibbon NotifyAgeCheckPassed OnAdEvent OnBadgeAwarded OnBecomeActive OnBrowserTrackerLayerLoadingStatusChanged OnBubbleAdded OnCallInviteInvoked OnCallingRemoved OnCallingStateChange OnCameraCFrameReplicationRequest OnCaptureBegan OnCaptureEnded OnCaptureObjectShared OnCapturePermissionsPromptFinished OnCaptureShared OnChatWindowAdded OnClientEvent OnClientInvoke OnClose OnContextRegistered OnContextUnregistered OnConvertToPackageResult OnCreatorLayerLoadingStatusChanged OnCrossExperienceStarted OnCrossExperienceStopped OnDeafenVoiceAudio OnDemandVideoCompleteFromUI OnDetach OnDragAreaDoubleClicked OnDragAreaRightClicked OnGameLeft OnHide OnHttpResultApproved OnImmersiveBrandedAdDisclosureButtonActivated OnImportFromRoblox OnIncomingMessage OnIncomingMessageEvent OnInvoke OnInvokeSuspendOverride OnJavaScriptCall OnLuaThemeUpdated OnLuaUrl OnMessage OnMouseCaptureBegin OnMouseCaptureEnd OnNewData OnNewJoinAttempt OnNotificationDisplayed OnNotificationInteraction OnNotificationUpdateFromPlugin OnOpenConvertToPackagePlugin OnOpenGameSettings OnOpenManagePackagePlugin OnPinExperienceCompleted OnPluginInstalledFromToolbox OnPluginInstalledFromWeb OnPolo OnPromptSaveInstanceToRobloxAsync OnPublishAsPlugin OnPublishAttempt OnPublishPackageResult OnRecordingFinished OnRecordingStarted OnRedo OnResignActive OnSaveOrPublishPlaceToRoblox OnSavePromptFinished OnSaveToRoblox OnSensorOutputChanged OnServerEvent OnServerInvoke OnSetItem OnSharePromptFinished OnStart OnStateChanged OnStopped OnTeleport OnTestPlayerCountChanged OnUGCSubmitCompleted OnUndeafenVoiceAudio OnUndo OnUnhide OnUpdate OnUserChatSettingUpdateAsync OnUserLayerLoadingStatusChanged OnVideoCaptureShared OnWindowClosed OnWindowStateChanged Open Open9SliceEditor OpenAllowInventoryReadAccess OpenAttenuationCurveEditor OpenAttenuationCurveEditorSignal OpenAudioCompressorEditorSignal OpenAudioEqualizerEditorSignal OpenAuthPrompt OpenBrowserWindow OpenCapturePermissionsPrompt OpenDirectionalCurveEditor OpenDirectionalCurveEditorSignal OpenExceptionMessagePopup OpenExperienceDetailsPrompt OpenFileInWebBrowser OpenFolder OpenInBrowser_DONOTUSE OpenInputActionManagerSignal OpenLogsFolder OpenNativeOverlay OpenPlace OpenPromptCreateOufit OpenPromptDeleteOutfit OpenPromptRenameOutfit OpenPromptSaveAvatar OpenPromptSetFavorite OpenPromptUpdateOutfit OpenPublishResultModal OpenSaveCapturesPrompt OpenScreenshotsFolder OpenScript OpenScriptAtLine OpenScriptDocumentAsync OpenSelfieConsent OpenSelfieQRCode OpenShareCapturePrompt OpenShareSheetWithLink OpenShop OpenShopRequested OpenStringValueDocumentAsync OpenStyleEditor OpenTemporaryDocumentAsync OpenUrl OpenVideosFolder OpenWeChatAuthWindow OpenWikiPage OpenWindow OpenWindowV2 Opened OperationCoalesced OperationEnqueued OptInPromptClosed OrientationChanged OutfitChanged Output OverrideStateChanged OverrideStatusChanged OverrideStreamingRadii OverrideStudioAction OverridesCleared PGSIsEnabled PageEnter PageLeave PanUnits ParameterChanged Participant ParticipantsStateChanged Pass Passed PasteRegion PathAdded PathChanged PathMoved PathRemoved Pause PauseSound Paused PerformBulkPurchase PerformCancelSubscription PerformCreateOutfitWithDescription PerformCreatorStorePurchase PerformDeleteOutfit PerformManagedUpdate PerformPurchase PerformPurchaseV2 PerformRenameOutfit PerformSaveAvatarWithDescription PerformSetFavorite PerformSubscriptionPurchase PerformSubscriptionPurchaseV2 PerformSubscriptionPurchaseV3Async PerformSubscriptionPurchaseWithRobuxAsync PerformUpdateOutfit PerformanceStatsVisibleChanged PersistentLoaded PhoneBookPromptClosed PickFileWithPromptAsync PickImageFileWithPrompt PickMeshFileWithPrompt PickMultipleFilesWithPrompt PinExperience PinStreamingForInstance PinStreamingForInstanceByUniqueId PivotTo PlaceJoinStateChanged PlatformStanding Play PlayEmote PlayEmoteAndGetAnimTrackById PlayEmoteAsync PlayFailed PlayLocalSound PlaySound PlaybackCompleted PlaybackStatusUpdated Played PlayerAdded PlayerCanMakePurchases PlayerChatAvailabilityStatusChanged PlayerChatted PlayerConnecting PlayerDisconnecting PlayerHasPass PlayerMembershipChanged PlayerMicActivitySignalChange PlayerOwnsAsset PlayerOwnsAssetAsync PlayerOwnsBundle PlayerOwnsBundleAsync PlayerPartyDataChanged PlayerRejoining PlayerRemoved PlayerRemoving PluginDragDropped PluginDragEntered PluginDragLeft PluginDragMoved PointFocused PointerAction PointsAwarded PollClientFeatures PollServerFeatures Populate PostAsync PostAsyncFullUrl PostSimulation PreAnimation PreCaptureShared PreRender PreSimulation PreVideoCaptureShared PrefetchDownloadStatusChanged Preload PreloadAsync PrepareAvatarForPreviewAsync PrepareCollectiblesPurchase PrepareCollectiblesPurchaseRequested PrepareCommerceProductPurchase PrepareProjectionMeshDataAsync Pressed PreviewNotificationSignal PreviewTexture Previous Print PrintHello ProcessAssetInsertionDrag ProcessAssetInsertionDrop ProcessCommand ProcessReceipt ProgressUpdate PromptAgeCheck PromptAgeCheckRequested PromptAllowInventoryReadAccess PromptAllowInventoryReadAccessCompleted PromptApplyProfileConfigurationCompleted PromptBulkPurchase PromptBulkPurchaseFinished PromptBulkPurchaseRefreshed PromptBulkPurchaseRequested PromptBulkPurchaseRequestedV2 PromptBulkPurchaseRequestedV3 PromptBundlePurchase PromptBundlePurchaseFinished PromptBundlePurchaseRequested PromptButtonHoldBegan PromptButtonHoldEnded PromptCancelSubscription PromptCancelSubscriptionRequested PromptCaptureGalleryPermissionAsync PromptClosePlace PromptCollectibleBundlePurchaseRequested PromptCollectiblesPurchase PromptCollectiblesPurchaseRequested PromptCommerceProductPurchase PromptCommerceProductPurchaseFinished PromptCommerceProductPurchaseRequested PromptCreateAvatarAssetAsync PromptCreateAvatarAsync PromptCreateMakeupAsync PromptCreateOutfit PromptCreateOutfitCompleted PromptCreatePlatformContentAsync PromptDeleteOutfit PromptDeleteOutfitCompleted PromptDownloadGameTableToCSV PromptExperienceDetailsAsync PromptExperienceDetailsCompleted PromptExportToCSVs PromptFeedbackSubmissionAsync PromptForExistingAssetId PromptForExistingAssetIdAsync PromptGameInvite PromptGamePassPurchase PromptGamePassPurchaseFinished PromptGamePassPurchaseRequested PromptHidden PromptImportAnimationClipFromVideoAsync PromptImportFile PromptImportFileAsync PromptImportFiles PromptImportFilesAsync PromptImportFromCSVs PromptInviteRequested PromptIrisInviteRequested PromptJoinAsync PromptJoinCompleted PromptLinkSharing PromptLinkSharingAsync PromptLogin PromptNativePurchase PromptNativePurchaseWithLocalPlayer PromptNativePurchaseWithLocalPlayerWithPaymentSessionId PromptNativePurchaseWithPaymentSessionId PromptOptIn PromptOptInRequested PromptPhoneBook PromptPremiumPurchase PromptPremiumPurchaseFinished PromptPremiumPurchaseRequested PromptProductPurchase PromptProductPurchaseFinished PromptProductPurchaseRequested PromptPurchase PromptPurchaseFinished PromptPurchaseRequested PromptPurchaseRequestedV2 PromptRealWorldCommerceBrowser PromptRenameOutfit PromptRenameOutfitCompleted PromptRobloxPurchase PromptRobloxPurchaseRequested PromptRobloxSubscriptionPurchase PromptRobloxSubscriptionPurchaseFinished PromptRobloxSubscriptionPurchaseRequested PromptRobuxTransferAsync PromptRobuxTransferRequested PromptRobuxTransferSubscriptionUpsellRequested PromptRsvpToEventAsync PromptRsvpToEventCompleted PromptSaveAvatar PromptSaveAvatarCompleted PromptSaveAvatarThumbnailCustomizationCompleted PromptSaveCapturesToGallery PromptSaveInstanceToRobloxAsync PromptSaveSelection PromptSaveSelectionAsync PromptSecurityChallengeAsync PromptSelectAvatarGenerationImageAsync PromptSetFavorite PromptSetFavoriteCompleted PromptShareCapture PromptShown PromptSubscriptionPurchase PromptSubscriptionPurchaseFinished PromptSubscriptionPurchaseRequested PromptThirdPartyPurchase PromptTransformPluginCheckEnable PromptTriggerEnded PromptTriggered PromptUpdateOutfit PromptUpdateOutfitCompleted PromptUploadCSVToGameTable PromptVIPServerPurchase PromptVIPServerPurchaseRequested Publish PublishAs PublishAsync PublishCageMeshAsync PublishDescendantAssets PublishDescendantAssetsAsync PublishPackage PublishPause PublishProtocolMethodRequest PublishProtocolMethodResponse PublishThenTurnOnTeamCreate PurchaseBrowserClosed PurchasePromptShown QueryDescendants QueuePositionChanged RCCProfilerDataComplete Ragdoll RankProductsAsync Raycast RaycastCachedTerrain RaycastLocal RccConnectionChanged RccEventReceived ReachedTarget ReadAsync ReadBufferAsync ReadCapturesFromGalleryAsync ReadPixelsBuffer ReadTextContentAsync ReadVoxelChannels ReadVoxels ReadVoxelsAsync_beta Ready RebalanceTeams ReceiveIncomingCall Received ReceivedUpdate ReceiverConnected ReceiverDisconnected RecentApiGamesFromRegistryUpdatedSignal RecenterUserHeadCFrame RecommendTopProductsAsync ReconcileCommunicationAccess ReconcileCommunicationAccessCompleted ReconnectTeleportInitFailed RecordAsync RecordingCompleted RedeemGamePassFreeTrial Redo References Refresh RefreshBulkPurchase RefreshBulkPurchaseRequested RefreshDocumentDisplayName RefreshPluginState RegionCodeWillHaveAutomaticNonCustomPolicies RegisterActiveAnimationClip RegisterActiveKeyframeSequence RegisterAdOpportunityAsync RegisterAlternateMesh RegisterAnimationClip RegisterAutocompleteCallback RegisterChatCallback RegisterCollisionGroup RegisterComputerCameraMovementMode RegisterComputerMovementMode RegisterContextIdFromLua RegisterCreatorLayers RegisterDefaultEncryptionKey RegisterDefaultSessionKey RegisterDisclosureButton RegisterEncryptedAsset RegisterEvaluationParallelCallback RegisterForExperienceJoin RegisterForExperienceLeave RegisterGetCore RegisterImpressionSource RegisterItemAsync RegisterKeyframeSequence RegisterLuaUrl RegisterOpenCloud RegisterPublishHold RegisterScriptAnalysisCallback RegisterSessionEncryptedAsset RegisterSetCore RegisterSuite RegisterTest RegisterTestLegacy RegisterTouchCameraMovementMode RegisterTouchMovementMode RegisterUGCValidationFunction RegisterUserLayers RegistrationComplete Release ReleaseAsync ReleaseContextFocus ReleaseFocus ReleaseRBXEventStream Released Remove RemoveAccessories RemoveAsync RemoveBone RemoveBreakpoint RemoveBreakpointById RemoveCenterDialog RemoveCharacter RemoveCollisionGroup RemoveControlPoint RemoveCustomStatus RemoveDefaultLoadingGuiSignal RemoveDefaultLoadingScreen RemoveDeviceAsync RemoveEmote RemoveEntry RemoveEntryValue RemoveFace RemoveGlobalPointsField RemoveGlobalPointsTag RemoveInputPin RemoveItem RemoveItemAsync RemoveKey RemoveKeyAtIndex RemoveKeyframe RemoveMarker RemoveMarkerAtIndex RemoveMetadata RemovePath RemovePathSubscribers RemovePersistentPlayer RemovePlace RemovePose RemovePreset RemoveReadOnlyReasonsAsync RemoveReplicationFocus RemoveReplicationFocusPosition RemoveScriptLineMarkers RemoveSelectionGroup RemoveSession RemoveSessionsWithMetadataKey RemoveSpecialKey RemoveStatus RemoveSubPose RemoveTag RemoveTargetLocale RemoveUnused RemoveValue RemoveVersionAsync RenameAlias RenameCollisionGroup RenameModel RenamePlace RenameToDefault RenderStepped RenderdocTriggerCapture ReplaceBodyPartR15 ReplaceMaterial ReplaceMaterialInTransform ReplaceMaterialInTransformSubregion ReplaceMaterialInTransformSubregionSlot ReplaceSession ReportAbuse ReportAbuseV3 ReportAssetSale ReportAvatarAbuse ReportBuildUIClose ReportBuildUIOpen ReportCapturesUIClose ReportCapturesUIOpen ReportChatAbuse ReportChatLineReportingClose ReportChatLineReportingOpen ReportChatSuspensionDialogClose ReportChatSuspensionDialogOpen ReportCounter ReportInfluxSeries ReportLog ReportLuaRequireCount ReportMenuTabClose ReportMenuTabOpen ReportMultipleLogs ReportPartyChatWindowClose ReportPartyChatWindowOpen ReportRobuxUpsellStarted ReportStats ReportToDiagByCountryCode ReportUGCValidationCounter ReportUGCValidationFailureTelemetry ReportUGCValidationTelemetry RequestAccessTokenScopesAsync RequestAsync RequestAvatarAutosetupAsync RequestAvatarGenerationSessionAsync RequestCompleted RequestFlushAsync RequestFlyToCollaborator RequestFocus RequestFriendship RequestHttpResultApproved RequestInitiated RequestInternal RequestLimitedAsync RequestModerationModeEnabled RequestNavigation RequestRCCProfilerData RequestRaise RequestScreenshotPermissionAsync RequestSeat RequestServerHttpResult RequestServerOutput RequestServerStats RequestSetSelectionAsync RequestStreamAroundAsync RequestTool RequestValidationAsync Require RequireLegacy ReserveServer ReserveServerAsync Reset ResetCollisionFidelity ResetCollisionFidelityWithEditableMeshDataLua ResetGraph ResetHarmonyMemoryTarget ResetHighlight ResetKeyboardMode ResetLocalPlayer ResetMaterialSlot ResetNormal ResetOnboardingCompleted ResetOrientationToIdentity ResetPropertyToDefault ResetScrollVelocity ResetTestControl ResetTestRegistry ResetWaterFlowMap ResetWaypoints Resize ResolveAnnotation ResolveContent ResolveModulePath ResolveSaveInstanceToRoblox ResolveStateForUser RestartDrag Restore RestoreBranchAsync RestoreScripts Resume ResumeSound Resumed Resuming RetrieveCaptures ReturnPressedFromOnScreenKeyboard ReturnToJavaScript ReturnToPublisherExperience RevealFileInFolder RevealPinnedExperience RevertAttributeOverridesAsync RevertInstanceOverridesAsync RevertPropertyOverridesAsync ReviewableTextEditsAsync RevokeFriendship RewardedVideoAdEnded RewardedVideoAdStarted RightMouseClick Roblox17sConnectionChanged Roblox17sEventReceived RobloxConnectionChanged RobloxEventReceived RobloxGuiFocusedChanged RobloxOnlyTranslate RobuxTransferCompleted Rollback Run RunAsync RunMoreCode RunTest RunTestsAsync Running RuntimeContentFail RuntimeContentQuery RuntimeContentShare SafeZoneOffsetsChanged SampleDirectional SampleImageProjected SampleUniform SaveBoolean SaveCaptureObjectToExternalStorage SaveCaptureToExternalStorage SaveCapturesToExternalStorageAsync SaveData SaveInstance SaveLocallyAsComplete SaveNumber SaveOrPublishPlaceToRobloxIsCanceled SavePlace SavePlaceAsync SavePreset SaveScreenshotCapture SaveScriptProfilingData SaveSelectedToRoblox SaveState SaveString SaveVideoCaptureToExternalStorage ScaleAsync ScaleTo ScheduleNotification ScopeCheckUIComplete ScopeTime ScreenPointToRay Screenshot ScreenshotContentReady ScreenshotReady ScreenshotSavedToAlbum ScreenshotUploaded ScriptAdded ScriptBeingRemoved ScriptChanged ScriptFullNameChanged ScriptSourceChanged Scroll ScrollStateChanged ScrollToTop SearchAudio SearchAudioAsync SearchCatalog SearchCatalogAsync Seated SecondaryActivated SegmentMeshAsync Select SelectRibbonTool Selected SelectionChanged SelectionChangedThisFrame SelectionGained SelectionLost SelfViewHidden SelfViewVisible Send SendAccelerometerEvent SendAppUISizes SendAsync SendCommand SendCoreUiNotification SendCreateInstanceFromStudio SendDeleteInstanceFromStudio SendDictatedSpeechAsync SendDictatedSpeechUniverseChatAsync SendEnableChatButtonClicked SendEnableChatButtonShown SendEventDeferred SendEventImmediately SendExpChatLoadSuccess SendExpChatMessageClientRendered SendExpChatWindowScroll SendExpChatWindowStatusChange SendGravityEvent SendGyroscopeEvent SendInternalAsync SendKey SendKeyEvent SendMessage SendMouseButton SendMouseButtonEvent SendMouseDelta SendMouseMoveDeltaEvent SendMouseMoveEvent SendMousePosition SendMouseWheelEvent SendNotification SendPointerAction SendPresetAsync SendReparentInstanceFromStudio SendReport SendScroll SendTerrainChangeFromStudio SendTextChatCommandClientSent SendTextInput SendTextInputCharacterEvent SendTouchEvent SendUIOcclusionMetricsForQueryRegion SendUniverseChatMessageAsync SendUniverseChatPresetAsync SendUpdate SendingMessage SendingUniverseChatMessage Sense Separate SerializeInstances SerializeInstancesAsync ServerCollectConditionalResult ServerCollectResult ServerContextOut ServerHttpResultOut ServerLifecycleChanged ServerLoadAnnotationReplies ServerLoadAnnotations ServerLoadResolvedAnnotations ServerLowMemoryWarning ServerMessageOut ServerMultiGetCanCollaborateRequested ServerPurchaseVerification ServerRequestData ServerRequestDataAsync ServerRestartScheduled ServerStart ServerStop ServiceAdded ServiceRemoving ServiceVisibilityChanged SessionChanged SessionExists Set Set3dRenderingEnabled SetAbsolutePosition SetAbsoluteSize SetAccessories SetAccountAge SetActive SetAdGuiInteractivityHandlerInitialized SetAdorneeOffsetFromAbsolutePosition SetAllowInventoryReadAccess SetAngleAttenuation SetAsync SetAttribute SetAudioApiByDefault SetAutoUpdate SetAvatarUnificationMode SetAxis SetBaseMaterialOverride SetBaseUrl SetBatchWindowDelay SetBlockListInitialized SetBoneCFrame SetBoneIsVirtual SetBoneName SetBoneParent SetBreakpoint SetBubbleChatSettings SetCageMeshContent SetCameraPanMode SetCameraYInvertVisible SetCell SetCells SetCharacterAppearanceJson SetChatStyle SetChatTranslationSettingsLocaleId SetChildBreakpointEnabledByScriptAndContext SetClickToWalkEnabled SetColor SetColorAlpha SetCondition SetConditions SetContent SetContents SetContextEnabled SetContinueExecution SetControlPoints SetCore SetCoreGuiEnabled SetCurrentDeviceId SetCurrentMaterial SetCurrentOrientation SetCurrentThreadId SetCustomSortFunction SetCustomTitleBarHeight SetDefaultLoadingGuiRemoved SetDefaultPropertyTransition SetDefaultValue SetDerives SetDescription SetDesiredAngle SetDeviceAsync SetDirectChatRequester SetDistanceAttenuation SetDragStyleFunction SetDropdownActive SetEmotes SetEmotesMenuOpen SetEmulatedPolicyInfo SetEnableContentImageSizeChangedEvents SetEnabled SetEntries SetEntry SetEntryContext SetEntryExample SetEntryKey SetEntrySource SetEntryValue SetEquippedEmotes SetExceptionBreakMode SetExperienceSettingsLocaleId SetExperimentalFeatures SetFFlagOverrides SetFaceColors SetFaceNormals SetFaceUVs SetFaceVertices SetFacsBonePose SetFacsCorrectivePose SetFacsPose SetFastFlagForTesting SetFastIntForTesting SetFastStringForTesting SetField SetFilter SetFingerControl SetFingerTip SetFixedSize SetFlagVersion SetFocusLock SetForcedPop SetGamepadCameraSensitivityVisible SetGamepadCursorPosition SetGameplayPausedNotificationEnabled SetGlobal SetGlobalGuiInset SetGuiObject SetHardwareSafeAreaInsets SetHarmonyMemoryTarget SetHasRobloxSubscription SetHttpEnabled SetIdentityOrientation SetImage SetImageServerView SetImportHeightmapPaused SetInputDevice SetInputTypesToIgnore SetInsertPoint SetInspectMenuEnabled SetIsEmulationEnabled SetIsExemptFromUGCAnalytics SetIsLoaded SetItem SetJoinAfterMoveInstance SetJoinAfterMoveTarget SetJoint SetJointRangeMax SetJointRangeMin SetJointSize SetKeyDown SetKeyUp SetKeys SetLegacyMaxItems SetLine SetListener SetLocal SetLocalPlayerInfo SetMaterialColor SetMaterialInTransform SetMaterialInTransformSubregion SetMaterialInTransformSubregionSlot SetMaterialSlot SetMembershipType SetMenuIsOpen SetMergeResolution SetMeshIdBlocking SetMeshPartHeadsAndAccessories SetMetadata SetMicDevice SetMinSize SetMinutesAfterMidnight SetMockInputAsync SetModerationAccessKey SetMotor SetMuted SetNavigationGamepad SetNetworkOwner SetNetworkOwnershipAuto SetNormal SetOnNextClicked SetOnboardingCompleted SetOrderedInputPinNames SetOrientationAsync SetOutgoingKBPSLimit SetOutputDevice SetPackageVersion SetParameter SetPartCollisionGroup SetPermissionPolicyFunction SetPermissions SetPhysicsThrottleEnabled SetPixelDensityAsync SetPlaceId SetPlaybackFrame SetPlaybackMode SetPlaybackPercentage SetPlayerIsUsing SetPlayerPartyId SetPluginEnabled SetPosition SetPostProcessEnabled SetPredictionMode SetPrimaryPart SetPrimaryPartCFrame SetProperties SetProperty SetPropertyTransition SetPropertyTransitions SetPurchasePromptIsShown SetRBXEvent SetRBXEventStream SetRateLimitForRequestType SetReady SetRecordingDevice SetRemoveOnHit SetRequestHandler SetResolutionAsync SetResolutionScale SetResponseDelay SetRobloxGuiFocused SetRobloxLocaleId SetRoll SetSafeZoneOffsets SetScalingModeAsync SetScriptLineMarker SetSdk SetSecondaryAxis SetServerAttribute SetServiceVisibilityPreference SetSession SetSetting SetSharedTable SetSoundEnabled SetStateEnabled SetStateFieldValue SetStudioPreview SetStyleRules SetSuperSafeChat SetTargetInstance SetTeamCreateOnPublishInfo SetTeleportData SetTeleportGui SetTeleportSetting SetTerrainSelectionHack SetTestControl SetTestingValue SetTextFromInput SetTextureOffset SetTimeout SetTintMode SetTitle SetTitleBarMode SetTokens SetTopbarInset SetTopbarTransparency SetTouchpadMode SetTposeAdjustment SetTutorialCompletionStatus SetTutorialState SetUIScaleMultiplier SetUV SetUiMessage SetUnder13 SetUniverseDisplayName SetUniverseId SetUploadNames SetUpvalue SetUriScript SetUserActivity SetUserDataAsync SetUserGuiRendering SetUserIdAccessList SetValue SetVariable SetVertexBoneWeights SetVertexBones SetVertexFaceColor SetVertexFaceNormal SetVertexFaceUV SetVolume SetWatchExpressions SetWaterCell SetWaveformKeys SetWaypoint Shapecast ShareSheetClosed ShouldDeliverCallback ShouldLaunchTutorial ShouldRenderTitleBarControlsNatively ShouldShowLuaNotificationOnPinExperienceCompleted ShowAccountPicker ShowAsync ShowBulkImportView ShowCameraSpeed ShowDiffsAgainstBase ShowDiffsAgainstServer ShowDynamicEudsaDisclosure ShowFeatureInterventionDetails ShowFeatureInterventionDetailsV2 ShowInviteFriendsUI ShowJoinPrompt ShowLeaveConfirmation ShowNotification ShowPackageDetails ShowPermissibleJoints ShowProfile ShowPromptFeedbackSubmission ShowPromptFeedbackUnavailable ShowPromptRsvpToEvent ShowPublishToRoblox ShowReportAdPopup ShowRewardedVideoAdAsync ShowRewardedVideoAdAtClientAsync ShowSaveOrPublishPlaceToRoblox ShowSaveToRoblox ShowSelfView ShowSourceDiffsAgainstCurrent ShowStatsBasedOnInputString ShowVideoAd ShowVolumes ShowWidgets Shutdown Signal SignalAssetTypePurchased SignalChallengeAbandoned SignalChallengeCompleted SignalChallengeInvalidated SignalChallengeLoaded SignalChallengeRequired SignalCheckPlayerHasRobloxSubscription SignalClientPurchaseSuccess SignalCreateOutfitFailed SignalCreateOutfitPermissionDenied SignalDeleteOutfitFailed SignalDeleteOutfitPermissionDenied SignalDialogChoiceSelected SignalFeedbackSubmissionCompleted SignalFeedbackSubmissionPermissionDenied SignalMockPurchasePremium SignalMockPurchaseRobloxSubscription SignalProfilingCapture SignalProfilingStart SignalProfilingStop SignalPromptBulkPurchaseFinished SignalPromptBundlePurchaseFinished SignalPromptCommerceProductPurchaseFinished SignalPromptGamePassPurchaseFinished SignalPromptPremiumPurchaseFinished SignalPromptProductPurchaseFinished SignalPromptPurchaseFinished SignalPromptRobloxSubscriptionPurchaseFinished SignalPromptSubscriptionPurchaseFinished SignalRenameOutfitFailed SignalRenameOutfitPermissionDenied SignalRobuxTransferCompleted SignalSaveAvatarFailed SignalSaveAvatarPermissionDenied SignalServerLuaDialogClosed SignalSetFavoriteFailed SignalSetFavoritePermissionDenied SignalUpdateOutfitFailed SignalUpdateOutfitPermissionDenied SignalUserSubscriptionStatusChanged Simulate SimulationRadiusChanged SingleFileChanged Sit SmoothDamp SmoothRegion SmoothRegionMaterialSlots Solve SourceValueChanged SpecialKeyPressed Spherecast Start StartAudioCaptureAsync StartCall StartCrossExperience StartDecalDrag StartDrag StartLuaUrlDelivery StartMergeAsync StartPlaySolo StartPlaying StartPlayingJSON StartRecording StartSessionWithPath StartSessionWithPathAsync StartSingleFileWatch StartSingleMeshImport StartSpan StartTask StartTestSession StartTextScraper StartUploadCaptureAsync StartUploadCaptureForSupportTicketAsync StartVideoCaptureAsync StartVideoCaptureForMCPAsync StartVideoCaptureInternalAsync StartVideoGenSessionAsync StartWatchingScriptLine Started StateChanged StateEnabledChanged StatsReceived Status StatusAdded StatusBarTapped StatusChanged StatusRemoved StatusReported Step StepAnimations StepAnimationsInternal StepIn StepOut StepOver StepPhysics Stepped Stop StopAllSounds StopAudioCaptureAsync StopCrossExperience StopLuaUrlDelivery StopPlaySolo StopPlaying StopRecording StopSimulationAsync StopSingleFileWatch StopTestSession StopTextScraper StopVideoCapture StopVideoCaptureAsync StopVideoCaptureForMCP StopVideoCaptureInternal Stopped StoppedTouching StoreWasCleared Strafing StreamingPinComplete StripComments StudioModeChanged StyleRulePropertyChanged StyleRulesChanged StyledPropertiesChanged SubmitAdNotification SubmitStratusBugReport Subscribe SubscribeAsync SubscribeBlock SubscribePause SubscribePauseAll SubscribeRetry SubscribeToProtocolMethodRequest SubscribeToProtocolMethodResponse SubscribeToRccEventNamespace SubscribeToTopic SubscribeUnblock SubstituteGeometry SubtractAsync SupportsSwitchToSettingsApp SweepPartAsync Swimming SwitchToSettingsApp SwitchedToAppShellFeature SyncStatusChanged SynchronizeWith SyncingCollaboratorsChanged TagAdded TagEmoteAnimation TagRemoved TakeDamage TakeScreenshot TakeScreenshotCaptureAsync TakeSnapshot TeamChat TeamCreateErrorStatus Teleport TeleportAsync TeleportCancel TeleportInitFailed TeleportPartyAsync TeleportReconnect TeleportSwitchServer TeleportToPlaceInstance TeleportToPrivateServer TeleportToSpawnByName TeleportTrustedBackForth TeleportTrustedBackHistory TeleportedPlacesBackHistory TeleportedUniversesBackHistory TempSetMicMutedToggleMic TestFramesCountdownAboutToStart TestRegistryChanged TextBoxFocusReleased TextBoxFocused TextChannelWindowAdded TextChannelWindowRemoved TextDocumentDidChange TextDocumentDidClose TextDocumentDidOpen ThemeChanged ThirdPartyPurchaseFinished TiltUnits TimeoutChatAttempt ToggleCaptureMode ToggleFullscreen ToggleGuiIsVisibleForCaptures ToggleGuiIsVisibleIfAllowed ToggleMaterialFillToolEnabled ToggleNotificationTray TogglePause ToggleRecording ToggleSelect ToggleSelectionHighlights ToggleSelectionHighlightsSignal ToggleTeamCreate TopbarTransparencyChangedSignal TopicNotificationReceived TopicSubscriptionError TopicTokenExpiry TorqueToAngularAcceleration TouchCameraMovementModeRegistered TouchDrag TouchEnded TouchLongPress TouchMoved TouchMovementModeRegistered TouchPan TouchPinch TouchRotate TouchStarted TouchSwipe TouchTap TouchTapInWorld Touched TouchpadModeChanged TrackEvent TrackEventWithArgs TrackerError TrackerPrompt TranscodeMesh TranscodeModel TranscodePropertySet Translate TranslateBy Triangulate TriggerEnded TriggerOnLandingPageMount TriggerOnLuaAppInteractive TriggerOnLuaAppReadyToRender TriggerOnPageMilestone Triggered TryBeginRecording TryInstallPlugin TweenPosition TweenPositionInternal TweenSize TweenSizeAndPosition TweenSizeAndPositionInternal TweenSizeInternal TypeKey UgcValidationFailure UgcValidationSuccess UiMessageChanged UnbanAsync UnbindAction UnbindActivate UnbindAllActions UnbindButton UnbindCoreAction UnbindCoreActivate UnbindFromRenderStep UnblockAsync Unblocked UnclampAsync Undo UnequipTools Unequipped UninstallPlugin Union UnionAsync UniverseChatChannelAllocated UniverseChatMessageReceived UniverseMetadataLoaded UnjoinFromOutsiders Unload Unloading UnpinStreamingForInstance UnregisterAdOpportunity UnregisterCollisionGroup UnregisterDefaultEncryptionKey UnregisterEncryptedAsset UnsubscribeFromTopic UpdateAllPackages UpdateAsync UpdateAvailable UpdateBranchAsync UpdateControlPoint UpdateDeviceAsync UpdateDeviceCFrame UpdateFields UpdateGraphNodeDefinition UpdateGraphNodeProperty UpdateHeartbeatObject UpdateItemAsync UpdatePlayerBlocked UpdatePlayerPartyData UpdatePluginManagement UpdatePublishedPackage UpdateSelectedFrame UpdateSourceAsync UpdateState UpdateStatusChanged UpdateToLatestVersion UpdateUI UpdateUnitTestOnly UpdateVideoGenSessionPromptAsync UpdateVideoGenSessionTriggersAsync UpgradeTempAssetId Upload UploadAndInsertAssetForJobAsync UploadAssetFromContentAsync UploadAssetFromPathAsync UploadCaptureAndPostMoment UploadCaptureAsync UploadComplete UploadPostAsync UploadProgress UploadVersionedAssetFromContentAsync UploadVersionedAssetFromPathAsync UrlEncode UserCFrameChanged UserCFrameEnabled UserCaptureSaved UserEligibleForRealWorldCommerceAsync UserGuiRenderingChanged UserHasBadge UserHasBadgeAsync UserMessageIntentSent UserOwnsGamePassAsync UserSubscriptionStatusChanged UserVideoCaptureFailed UserVideoCaptureStartFailed ValidateDynamicHeadEditableMesh ValidateEditableMeshCageMeshIntersection ValidateEditableMeshCageNonManifoldAndHoles ValidateEditableMeshCageUVCoincident ValidateEditableMeshCageUVTriangleArea ValidateEditableMeshFacialBounds ValidateEditableMeshFacialExpressiveness ValidateEditableMeshFullBodyCageDeletion ValidateEditableMeshMisMatchUV ValidateEditableMeshOverlappingVertices ValidateEditableMeshTriangleArea ValidateEditableMeshTriangles ValidateEditableMeshUVDuplicates ValidateEditableMeshUVSpace ValidateEditableMeshUVValuesInReference ValidateEditableMeshUniqueUVCount ValidateEditableMeshVertColors ValidateHSRMeshIds ValidateLeaderSkinnedVertsNearCageIslands ValidatePartBBoxAfterFullFacs ValidatePropertiesSensible ValidateSkinnedEditableMesh ValidateUGCAccessoryAsync ValidateUGCBodyPartAsync ValidateUGCFullBodyAsync VerticesModified VideoAdClosed VideoCaptureInProgress VideoRecordingChangeRequest ViewPackageOnWebsite ViewportChanged ViewportDragDropped ViewportDragEntered ViewportDragLeft ViewportPointToRay VoiceChatStatsCollected WaitForChild WaitForDataReady WaitForGenerationAsync WaitForInputEventsProcessed Warn WatchAdded WatchRemoved WheelBackward WheelForward WhenLoaded WhisperChat WillLimitLayeredAccessoryAsync WindowFocusReleased WindowFocused WiringChanged WorldToCell WorldToCellPreferEmpty WorldToCellPreferSolid WorldToScreenPoint WorldToViewportPoint WriteActivityHistoryEventFromStudio WriteAppend WritePixelsBuffer WriteVoxelChannels WriteVoxels WriteVoxelsAsync_beta X Y Z Zoom ZoomToExtents adGuiRegisterUI adGuiStateChanged addItem applyPartyIdToPlayer bindButton breakJoints changed childAdded children clone destroy deviceMeetsRequirementsForFeature equipped findFirstChild findPartOnRay findPartsInRegion3 fire forwardStateToLuaUI generateTempUrlInContentProvider getButton getChildren getDaysSinceFirstUserLogin getExtrapolation getGameTime getInternalChannelId getInternalGroupId getInternalPublishPause getInternalSessionId getInternalSubscribePause getInternalSubscribePauseAll getInternalVoiceChatApiVersion getLocalGamesFromRegistry getMass getMinutesAfterMidnight getPlayers getRecentAPIGamesFromRegistry getService getSystemTheme getSystemThemeAsync getTempUrlInContentProvider getTestSessionProviderStats getThrottleFramerateEnabled getVideoLod isA isAppRatingPromptAvailable isAudioEnabled isDescendantOf isFeatureEnabled isFriendsWith isInternalPublishPaused isSystemThemeAvailable isTutorialBannerClosed isTutorialPopupClosed isVideoEnabled joinVoice keyDown lastForce lastVoiceChatConnectivity lastVoiceChatStats lastVoiceChatSubscriptions leaveVoice loadAnimation loadAsset loadBoolean loadInstance loadNumber loadString makeJoints mouseClick move moveTo notifyServerACSCleanup onDemandVideoPlayInUI openLink openLocalFile openPlace pause play playerFromCharacter players refreshAvatarThumbnails rejoinVoice remove removeAPIGameFromRegistry removeLocalFileFromRegistry resize saveBoolean saveInstance saveNumber saveString sendRobloxEvent sendThemeChangeEvent service setAppIcon setClassicThemeActive setMinutesAfterMidnight setModerationModeEnabled setTheme setThrottleFramerateEnabled setTutorialBannerClosed setTutorialPopupClosed shouldShowMacOSDeprecationWarning shouldShowWinOSDeprecationWarning showAppRatingPrompt startTutorial stop takeDamage unequipped usesCustomRestPoseLua waitForDataReady willRemoveAccessory]]
	for w in string.gmatch(s, "[%w_]+") do
		ALL_API_METHODS[w] = true
	end
end
local ALL_API_EVENTS = {}

local ALL_ENUM_NAMES = {}
do
	local s = [[AccessModifierType AccessoryType ActionOnAutoResumeSync ActionOnStopSync ActionType ActivePayerStatus ActuatorRelativeTo ActuatorType AdAvailabilityResult AdEventType AdFormat AdShape AdTeleportMethod AdUIEventType AdUIType AdUnitStatus AdornCullingMode AdornShading AgeCheckStatus AlignType AlphaMode AnalyticsCustomFieldKeys AnalyticsEconomyAction AnalyticsEconomyFlowType AnalyticsEconomyTransactionType AnalyticsLogLevel AnalyticsProgressionStatus AnalyticsProgressionType AnimatedImageScaleType AnimationClipFromVideoStatus AnimationNodeBlend2DInputMode AnimationNodeBlendMode AnimationNodeInterruptible AnimationNodePhaseSync AnimationNodePlayMode AnimationNodeTransitionType AnimationNodeTransitionWhen AnimationNodeType AnimationNodeWaitFor AnimationPriority AnimationValueNodeType AnimatorRetargetingMode AnnotationChannelContentPreference AnnotationEditingMode AnnotationPlaceContentPreference AnnotationRequestStatus AnnotationRequestType AntiAliasing AppLifecycleManagerState AppShellActionType AppShellFeature AppUpdateStatus ApplyShadowMode ApplyStrokeMode AspectType AssetCreatorType AssetFetchStatus AssetRepresentation AssetType AssetTypeVerification AudioApiRollout AudioCaptureMode AudioChannelLayout AudioFilterType AudioPositionType AudioSampleFormat AudioSimulationFidelity AudioSortType AudioSubType AudioWindowSize AuthorityMode AutoIndentRule AutomaticSize AvatarAssetType AvatarChatServiceFeature AvatarContextMenuOption AvatarGenerationError AvatarItemType AvatarPromptResult AvatarSettingsAccessoryLimitMethod AvatarSettingsAccessoryMode AvatarSettingsAnimationClipsMode AvatarSettingsAnimationPacksMode AvatarSettingsAppearanceMode AvatarSettingsBuildMode AvatarSettingsCharacterControllerMode AvatarSettingsClothingMode AvatarSettingsCollisionMode AvatarSettingsCustomAccessoryMode AvatarSettingsCustomBodyType AvatarSettingsCustomClothingMode AvatarSettingsHitAndTouchDetectionMode AvatarSettingsJumpMode AvatarSettingsLegacyCollisionMode AvatarSettingsScaleMode AvatarThumbnailCustomizationType AvatarUnificationMode Axis BasicMeshPartShape BenefitType BinType BodyPart BodyPartR15 BorderMode BorderStrokePosition BranchStatus BreakReason BreakpointRemoveReason BulkMoveMode BundleType Button ButtonStyle CageType CameraMode CameraNavigationModel CameraPanMode CameraSpeedAdjustBinding CameraType CanCollaborateError CaptureGalleryPermission CaptureType CatalogCategoryFilter CatalogSortAggregation CatalogSortType CellBlock CellMaterial CellOrientation CenterDialogType CharacterControlMode ChatCallbackType ChatColor ChatMode ChatPrivacyMode ChatRestrictionStatus ChatStyle ChatVersion ClientAnimatorThrottlingMode CloseReason CollaboratorStatus CollisionFidelity CommandPermission CompileTarget CompletionAcceptanceBehavior CompletionItemKind CompletionItemTag CompletionTriggerKind CompositeValueCurveType CompressionAlgorithm ComputerCameraMovementMode ComputerMovementMode ConfigSnapshotErrorState ConnectionError ConnectionState ContentSourceType ContextActionPriority ContextActionResult ControlMode CoreGuiType CreateAssetResult CreateContentResult CreateOutfitFailure CreatorType CreatorTypeFilter CurrencyType CustomCameraMode DataModelChangeType DataModelExtractorFileType DataStoreRequestType DebugBreakModeType DebuggerEndReason DebuggerExceptionBreakMode DebuggerFrameType DebuggerPauseReason DebuggerResumeType DebuggerStatus DefaultScriptSyncFileType DevCameraOcclusionMode DevComputerCameraMovementMode DevComputerMovementMode DevTouchCameraMovementMode DevTouchMovementMode DeveloperMemoryTag DeviceFeatureType DeviceForm DeviceLevel DeviceSimulatorScalingMode DeviceType DialogBehaviorType DialogPurpose DialogTone DigitsRigDescriptionSide DiscountType DisplayScalingMode DisplaySize DistanceAttenuationMode DomainType DominantAxis DraftStatusCode DragDetectorDragStyle DragDetectorPermissionPolicy DragDetectorResponseStyle DraggerCoordinateSpace DraggerMovementMode DraggingScrollBar EasingDirection EasingStyle EditableStatus ElasticBehavior EmitterPositionType EngagementLevel EngineFolder EnviromentalPhysicsThrottle ExperienceActivationStatus ExperienceAuthScope ExperienceEventStatus ExperienceStateCaptureSelectionMode ExperienceStateRecordingLoadMode ExperienceStateRecordingLoadSourceType ExperienceStateRecordingPlaybackMode ExplosionType ExternalEditorMode FACSDataLod FacialAgeEstimationResultType FacialAnimationStreamingState FacsActionUnit FeatureChannelEncoding FeatureNormalization FeatureRestrictionAbuseVector FeedbackType FieldOfViewMode FillDirection FilterErrorType FilterResult FilterType FinishRecordingOperation FluidFidelity FluidForces Font FontSize FontStyle FontWeight ForceLimitMode FormFactor FrameStyle FramerateManagerMode FriendRequestEvent FriendStatus FriendsCallingEndReason FriendsCallingParticipantErrors FriendsCallingParticipantLeaveReason FriendsCallingParticipantStatus FriendsCallingPhase FrustumStreamingMode FunctionalTestResult GameAvatarType GamepadType GearGenreSetting GearType GenerateMomentTextResult Genre GradientTileMode GradientType GraphicsMode GraphicsOptimizationMode GroupMembershipStatus GuiState GuiType HandlesStyle HapticEffectType HashAlgorithm HighlightDepthMode HorizontalAlignment HoverAnimateSpeed HttpCachePolicy HttpCompression HttpContentType HttpError HttpRequestType HumanoidCollisionType HumanoidDisplayDistanceType HumanoidHealthDisplayType HumanoidRigType HumanoidStateType IKCollisionsMode IKControlConstraintSupport IKControlType IXPLoadingStatus ImageAlphaType ImageCombineType InOut InfoType InitialDockState InputActionType InputBindingType InputSink InputType InstanceFileSyncStatus IntentReplicability IntermediateMeshGenerationResult InternalVideoUsage InterpolationThrottlingMode InviteState ItemLineAlignment JoinSource JointCreationMode KeyCode KeyCodeStringFormat KeyInterpolationMode KeywordFilterType KnownWindow LeftRight LexemeType LightingStyle Limb LineJoinMode ListDisplayMode ListenerLocation ListenerPositionType ListenerType LiveEditingAtomicUpdateResponse LiveEditingBroadcastMessageType LoadCharacterLayeredClothing LoadDynamicHeads LocationType LuauTypeCheckMode MakeupType MarketplaceBulkPurchasePromptStatus MarketplaceItemPurchaseStatus MarketplaceProductType MarkupKind MatchmakingType Material MaterialPattern MembershipType MergeResolution MergeStatus MeshAttribute MeshPartDetailLevel MeshPartHeadsAndAccessories MeshScaleUnit MeshType MessageType MetadataFieldType ModelLevelOfDetail ModelStreamingBehavior ModelStreamingMode ModerationResultCategory ModerationResultLabel ModerationStatus ModifierKey MouseBehavior MoveState MuteState NameOcclusion NegateOperationHiddenHistory NetworkOwnership NetworkStatus NoiseType NormalId NotificationButtonType OperationType OrientationAlignmentMode OrthographicMode OutfitSource OutfitType OutputLayoutMode OverrideMouseIconBehavior PackagePermission PageMilestoneType PageType PartType ParticleEmitter2DEmissionMode ParticleEmitterShape ParticleEmitterShapeInOut ParticleEmitterShapeStyle ParticleFlipbookLayout ParticleFlipbookMode ParticleFlipbookTextureCompatible ParticleOrientation PathStatus PathWaypointAction PathfindingUseImprovedSearch PeoplePageLayout PerformanceOverlayMode PermissionLevelShown PhysicalConstraintType PhysicsSimulationRate PhysicsSteppingMethod PinExperienceStatus PioneerSource PlaceContentPreference PlacePublishType Platform PlaybackState PlayerActions PlayerCharacterDestroyBehavior PlayerChatType PlayerDataErrorState PlayerDataLoadFailureBehavior PlayerExitReason PlayerPlatformActivationStatus PlayerPlatformSpenderStatus PluginConnectionTargetType PoseEasingDirection PoseEasingStyle PositionAlignmentMode PredictionMode PredictionStatus PredictiveStreamingMode PreferredInput PreferredTextSize PrefetchDownloadStatus PrimalPhysicsSolver PrimitiveType PrivilegeType ProductLocationRestriction ProductPurchaseChannel ProductPurchaseDecision ProjectionType PromptCreateAssetResult PromptCreateAvatarResult PromptCreateOutfitResult PromptCreatePlatformContentResult PromptExperienceDetailsResult PromptLinkSharingResult PromptPublishAssetResult PropertyStatus ProximityPromptExclusivity ProximityPromptInputType ProximityPromptStyle PurchaseOption QualityLevel QueueDecision R15CollisionType RaycastFilterType ReadCapturesFromGalleryResult ReceiptDecision ReceiptType RecommendationActionType RecommendationDepartureIntent RecommendationImpressionType RecommendationItemContentType RecommendationItemVisibility RecommendationPreferenceTargetType RecommendationPreferenceType RejectCharacterDeletions RenderFidelity RenderPriority RenderingCacheOptimizationMode RenderingTestComparisonMethod ReplicateInstanceDestroySetting ReplicationMode ResamplerMode ReservedHighlightId RestPose RestPoseModel ReturnKeyType ReverbType ReviewableContentState RibbonTool RigLabel RigScale RigType RobuxTransferEligibility RollOffMode RolloutState RotationOrder RotationType RsvpStatus RtlTextSupport RunContext RunState RuntimeUndoBehavior SafeAreaCompatibility SalesTypeFilter SandboxedInstanceMode SaveAvatarThumbnailCustomizationFailure SaveFilter SavedQualitySetting ScaleType ScopeCheckResult ScreenInsets ScreenOrientation ScreenshotCaptureResult ScriptScannerUpdateType ScriptStoppedReason ScriptVariableScope ScrollBarInset ScrollState ScrollingDirection SecurityCapability SelectionBehavior SelectionRenderMode SelfViewPosition SensorMode SensorUpdateType ServerLiveEditingMode ServiceVisibility Severity ShowAdResult SignalBehavior SimulationMode SizeConstraint SlimTintMode SlimTranscoderStatus SlimViewContext SolverConvergenceMetricType SolverConvergenceVisualizationMode SortDirection SortOrder SpecialKey StartCorner StateObjectFieldType StateReferenceFrame Status StepFrequency StreamOutBehavior StreamingIntegrityMode StreamingPauseMode StrokeSizingMode StudioAction StudioCaptureBufferStatus StudioCaptureScreenshotFormat StudioCloseMode StudioDataModelType StudioPlaceUpdateFailureReason StudioScriptEditorColorCategories StudioScriptEditorColorPresets StudioStyleGuideColor StudioStyleGuideModifier Style SubscriptionExpirationReason SubscriptionPaymentStatus SubscriptionPeriod SubscriptionState SurfaceConstraint SurfaceGuiShape SurfaceGuiSizingMode SurfaceType SwipeDirection SystemThemeValue TableMajorAxis TeamCreateErrorState Technology TelemetryBackend TelemetryStandardizedField TeleportMethod TeleportResult TeleportState TeleportType TerrainAcquisitionMethod TerrainFace TerrainLiquidMergeOperation TerrainSolidMergeOperation TestCaseStatus TestRunStatus TextChannelDisplayMode TextChatMessageStatus TextDirection TextFilterContext TextInputType TextTruncate TextXAlignment TextYAlignment TextureMode TextureQueryType ThreadPoolConfig ThrottlingPriority ThumbnailSize ThumbnailType TickCountSampleMethod TitleBarControlsPosition TitleBarMode TonemapperPreset TopBottom TouchCameraMovementMode TouchMovementMode TrackerError TrackerExtrapolationFlagMode TrackerFaceTrackingStatus TrackerLodFlagMode TrackerLodValueMode TrackerMode TrackerPromptEvent TrackerType TriStateBoolean TweenStatus UIBlurStrength UICaptureMode UIDragDetectorBoundingBehavior UIDragDetectorDragRelativity UIDragDetectorDragSpace UIDragDetectorDragStyle UIDragDetectorResponseStyle UIDragSpeedAxisMapping UIFlexAlignment UIFlexMode UITheme UiMessageType UpdateState UploadCaptureResult UsageContext UserAcquisitionSource UserCFrame UserIdMode UserInputState UserInputType UserNewReturningStatus UserReturnStatus VRComfortSetting VRControllerModelMode VRDeviceType VRLaserPointerMode VRPresentationMode VRSafetyBubbleMode VRScaling VRSessionState VRTouchpad VRTouchpadMode VelocityConstraintMode VerifiedLevel VerticalAlignment VerticalScrollBarPosition VibrationMotor VideoCaptureResult VideoCaptureStartedResult VideoDeviceCaptureQuality VideoError VideoSampleSize ViewMode VirtualCursorMode VirtualInputMode VoiceChatDistanceAttenuationType VoiceChatState VoiceClientLeaveReasons VoiceControlPath VoiceRccReconnectReason VolumetricAudio WaterDirection WaterForce WebSocketState WebStreamClientState WebStreamClientType WeldConstraintPreserve WhenUserFirstPlayed WhisperChatPrivacyMode WindSoundProfile WindowState WrapLayerAutoSkin WrapLayerDebugMode WrapTargetDebugMode ZIndexBehavior]]
	for w in string.gmatch(s, "[%w_]+") do
		ALL_ENUM_NAMES[w] = true
	end
end


local serviceCache = {}

local function softSignal()
	local handlers = {}
	return setmetatable({
		Connect = function(_, fn)
			if type(fn) == "function" then handlers[#handlers + 1] = fn end
			return { Disconnect = function() end, Connected = true }
		end,
		Once = function(_, fn)
			if type(fn) == "function" then pcall(fn) end
			return { Disconnect = function() end, Connected = true }
		end,
		Wait = function() end,
		Fire = function(_, ...) for _, h in ipairs(handlers) do pcall(h, ...) end end,
	}, { __tostring = function() return "RBXScriptSignal" end })
end

local softInst
local softDepth = 0
softInst = function(className, name)
	if softDepth > 12 then
		return setmetatable({ClassName=className or "Folder", Name=name or "x"}, {
			__index = function() return function() end end,
			__newindex = function() end,
		})
	end
	softDepth = softDepth + 1
	className = className or "Instance"
	name = name or className
	local children, signals = {}, {}
	local props = {
		Name = name, ClassName = className, Parent = nil, Archivable = true,
		AbsoluteSize = { X = 1920, Y = 1080 }, AbsolutePosition = { X = 0, Y = 0 },
		Size = { X = { Scale = 0, Offset = 100 }, Y = { Scale = 0, Offset = 100 } },
		Position = { X = { Scale = 0, Offset = 0 }, Y = { Scale = 0, Offset = 0 } },
		Visible = true, Enabled = true, Text = "", Value = 0, Health = 100, MaxHealth = 100,
		WalkSpeed = 16, JumpPower = 50, UserId = 1, DisplayName = "Player",
		BackgroundTransparency = 0, TextTransparency = 0, ZIndex = 1, LayoutOrder = 0,
		ResetOnSpawn = true, IgnoreGuiInset = false, BackgroundColor3 = { R = 1, G = 1, B = 1 },
		TextColor3 = { R = 0, G = 0, B = 0 }, BorderSizePixel = 1, TextSize = 14,
		Anchored = true, CanCollide = true, CollisionGroup = "Default",
	}
	local function getSig(k)
		if not signals[k] then signals[k] = softSignal() end
		return signals[k]
	end
	local o = {}
	setmetatable(o, {
		__index = function(_, k)
			if type(k) == "string" and #k >= 2 and #k < 80 then
				emit("inst:key", k)
			end
			if props[k] ~= nil then return props[k] end
			if k == "WaitForChild" or k == "FindFirstChild" or k == "FindFirstChildOfClass"
				or k == "FindFirstChildWhichIsA" or k == "FindFirstAncestor" or k == "FindFirstAncestorOfClass"
				or k == "FindFirstDescendant" or k == "WaitForChildWhichIsA" then
				return function(_, n)
					n = tostring(n or "")
					if not children[n] then children[n] = softInst(n, n); children[n].Parent = o end
					return children[n]
				end
			end
			if k == "GetChildren" or k == "GetDescendants" then
				return function()
					local t = {}
					for _, v in pairs(children) do t[#t + 1] = v end
					return t
				end
			end
			if k == "GetService" or k == "FindService" then
				return function(_, sn)
					sn = tostring(sn or "")
					if not serviceCache[sn] then serviceCache[sn] = softInst(sn, sn) end
					return serviceCache[sn]
				end
			end
			if k == "IsA" then return function(_, cn) return cn == className or cn == "Instance" end end
			if k == "Clone" then return function() return softInst(className, name) end end
			if k == "Destroy" or k == "ClearAllChildren" or k == "Remove" then return function() end end
			if k == "GetFullName" then return function() return className .. "." .. tostring(props.Name) end end
			if k == "GetAttribute" then return function() return nil end end
			if k == "SetAttribute" then return function() end end
			if k == "GetAttributes" then return function() return {} end end
			if k == "GetPropertyChangedSignal" or k == "GetAttributeChangedSignal" then
				return function(_, prop) return getSig(tostring(prop)) end
			end
			if serviceCache[k] then return serviceCache[k] end
			if children[k] then return children[k] end
			if k == "LocalPlayer" or k == "Character" or k == "CurrentCamera" or k == "PrimaryPart"
				or k == "Parent" or k == "Terrain" or k == "PlayerGui" or k == "Backpack"
				or k == "StarterGear" or k == "PlayerScripts" or k == "Team" or k == "CameraSubject"
				or k == "Humanoid" or k == "Head" or k == "Torso" or k == "HumanoidRootPart" then
				if not children[k] then children[k] = softInst(k, k); children[k].Parent = o end
				return children[k]
			end
			if type(k) == "string" and string.match(k, "^[A-Z][%w]+$")
				and (string.match(k, "^Get") or string.match(k, "^Set") or string.match(k, "^Find")
					or string.match(k, "^Is") or string.match(k, "^Has") or string.match(k, "^Can")
					or string.match(k, "^Load") or string.match(k, "^Save") or string.match(k, "^Create")
					or string.match(k, "^Add") or string.match(k, "^Remove") or string.match(k, "^Clear")
					or string.match(k, "^Fire") or string.match(k, "^Invoke") or string.match(k, "^Bind")
					or string.match(k, "^Unbind") or string.match(k, "^Play") or string.match(k, "^Stop")
					or string.match(k, "^Pause") or string.match(k, "^Tween") or string.match(k, "^Kick")
					or string.match(k, "^Teleport") or string.match(k, "^Prompt") or string.match(k, "^Award")
					or string.match(k, "^Apply") or string.match(k, "^Wait") or string.match(k, "^Clone")
					or string.match(k, "^Destroy") or string.match(k, "^Connect") or string.match(k, "^Disconnect")
					or string.match(k, "^Http") or string.match(k, "^JSON") or string.match(k, "^Url")
					or string.match(k, "^Generate") or string.match(k, "^Request") or string.match(k, "^Publish")
					or string.match(k, "^Subscribe") or string.match(k, "^Filter") or string.match(k, "^Compute")
					or string.match(k, "^Pivot") or string.match(k, "^Move") or string.match(k, "^Scale")
					or string.match(k, "^Raycast") or string.match(k, "^Bulk") or string.match(k, "^Take")
					or string.match(k, "^Equip") or string.match(k, "^Change") or string.match(k, "^Register")
					or string.match(k, "^Send") or string.match(k, "^Display") or string.match(k, "^Capture")
					or string.match(k, "^Start") or string.match(k, "^Join") or string.match(k, "^Leave")
					or string.match(k, "^Screen") or string.match(k, "^World") or string.match(k, "^Viewport")
					or string.match(k, "^Emit") or string.match(k, "^Break") or string.match(k, "^Make")
					or string.match(k, "^Serialize") or string.match(k, "^Deserialize") or string.match(k, "^Adjust")
					or string.match(k, "^Replace") or string.match(k, "^Build") or string.match(k, "^Sit")
					or string.match(k, "^Jump") or string.match(k, "^Reserve") or string.match(k, "^Advance")
					or string.match(k, "^Perform") or string.match(k, "^AddTag") or string.match(k, "^RemoveTag")
					or string.match(k, "^UserOwns") or string.match(k, "^PlayerOwns") or string.match(k, "^UserHas")
				) then
				if string.match(k, "Added$") or string.match(k, "Removed$") or string.match(k, "Changed$")
					or string.match(k, "Ended$") or string.match(k, "Began$") or string.match(k, "Click$")
					or k == "Heartbeat" or k == "RenderStepped" or k == "Stepped" or k == "Event"
					or k == "OnClientEvent" or k == "OnServerEvent" or k == "Completed" or k == "Triggered" then
					return getSig(k)
				end
				return function(self, ...)
					-- log ALL string args (not just first)
					for ai = 1, select("#", ...) do
						local a = select(ai, ...)
						if type(a) == "string" and #a >= 1 then
							emit("api-arg:" .. k, a)
						end
					end
					local a1 = select(1, ...)
					if k == "JSONEncode" then return "{}" end
					if k == "JSONDecode" then return {} end
					if k == "GenerateGUID" then return "00000000-0000-0000-0000-000000000000" end
					if k == "UrlEncode" then return tostring(a1 or "") end
					if k == "GetAsync" or k == "HttpGet" or k == "HttpGetAsync"
						or k == "PostAsync" or k == "HttpPost" or k == "RequestAsync" then
						if type(a1) == "string" then emit("http-url", a1) end
						return ""
					end
					if k == "IsClient" or k == "IsRunning" then return true end
					if k == "IsServer" or k == "IsStudio" then return false end
					if k == "GetPlayers" then return { serviceCache.LocalPlayer or softInst("Player", "LocalPlayer") } end
					if k == "GetTextSize" then return { X = 50, Y = 20 } end
					if k == "GetMouseLocation" then return { X = 0, Y = 0 } end
					if k == "Create" then
						return { Play = function() end, Cancel = function() end, Pause = function() end, Completed = softSignal() }
					end
					if k == "CreatePath" then
						return { ComputeAsync = function() end, GetWaypoints = function() return {} end, Status = 0 }
					end
					if k == "GetDataStore" or k == "GetOrderedDataStore" or k == "GetGlobalDataStore" then
						return {
							GetAsync = function() return nil end, SetAsync = function() end,
							UpdateAsync = function(_, f) if type(f) == "function" then return f(nil) end end,
							RemoveAsync = function() end, OnUpdate = softSignal(),
						}
					end
					if string.sub(k, 1, 2) == "Is" or string.sub(k, 1, 3) == "Has" or string.sub(k, 1, 3) == "Can" then
						return false
					end
					if string.sub(k, 1, 3) == "Get" or string.sub(k, 1, 4) == "Find" or string.sub(k, 1, 4) == "Load" then
						return nil
					end
					return softInst(k .. "Result", k .. "Result")
				end
			end
			-- Full API: methods/events from dump
			if type(k) == "string" and ALL_API_METHODS and ALL_API_METHODS[k] then
				if string.match(k, "Added$") or string.match(k, "Removed$") or string.match(k, "Changed$")
					or string.match(k, "Ended$") or string.match(k, "Began$") or string.match(k, "Click$")
					or k == "Heartbeat" or k == "RenderStepped" or k == "Stepped" or k == "Event"
					or k == "OnClientEvent" or k == "OnServerEvent" or k == "Completed" or k == "Triggered"
					or k == "MouseButton1Click" or k == "MouseButton2Click" or k == "Activated" then
					return getSig(k)
				end
				return function(self, ...)
					for ai = 1, select("#", ...) do
						local a = select(ai, ...)
						if type(a) == "string" and #a >= 1 then emit("api-arg:" .. k, a) end
					end
					if k == "JSONEncode" then return "{}" end
					if k == "JSONDecode" then return {} end
					if k == "GenerateGUID" then return "00000000-0000-0000-0000-000000000000" end
					if string.sub(k, 1, 2) == "Is" or string.sub(k, 1, 3) == "Has" or string.sub(k, 1, 3) == "Can" then return false end
					if string.sub(k, 1, 3) == "Get" or string.sub(k, 1, 4) == "Find" then return nil end
					return nil
				end
			end
			if not children[k] then
				children[k] = softInst(tostring(k), tostring(k))
				children[k].Parent = o
			end
			return children[k]
		end,
		__newindex = function(_, k, v)
			props[k] = v
			if type(v) == "table" then children[k] = v end
			if type(v) == "string" and #v >= 1 then
				-- never log scaffold Player/Workspace names
				if v == "Player" or v == "LocalPlayer" or v == "Workspace" or v == "game" then return end
				if k == "Name" and (v == "Players" or v == "DataModel") then return end
				emit("prop:" .. tostring(k), v)
			end
		end,
		__tostring = function() return className end,
	})
	softDepth = softDepth - 1
	return o
end

for _, sn in ipairs(SERVICE_NAMES) do
	serviceCache[sn] = softInst(sn, sn)
end
local game = softInst("DataModel", "game")
serviceCache.Workspace = softInst("Workspace", "Workspace")
serviceCache.Players = softInst("Players", "Players")
local lp = softInst("Player", "LocalPlayer")
lp.UserId = 1
-- scaffold name set without emit
pcall(function() local mt = getmetatable(lp); end)
serviceCache.LocalPlayer = lp
serviceCache.Players.LocalPlayer = lp

-- Thick stubs for WRD env-detect dumps
do
	local function method(ret)
		return function() return ret end
	end
	local rs = serviceCache.RunService or softInst("RunService", "RunService")
	serviceCache.RunService = rs
	-- Prefer real-ish IsClient/IsRunning
	pcall(function()
		rs.IsClient = method(true)
		rs.IsServer = method(false)
		rs.IsRunning = method(true)
		rs.IsStudio = method(false)
	end)
	local ts = serviceCache.TextService or softInst("TextService", "TextService")
	serviceCache.TextService = ts
	pcall(function()
		ts.GetTextSize = function() return { X = 40, Y = 14 } end
	end)
	local gs = serviceCache.GuiService or softInst("GuiService", "GuiService")
	serviceCache.GuiService = gs
	pcall(function()
		gs.GetGuiInset = function() return { X = 0, Y = 36 }, { X = 0, Y = 0 } end
	end)
	local uis = serviceCache.UserInputService or softInst("UserInputService", "UserInputService")
	serviceCache.UserInputService = uis
	pcall(function()
		uis.IsKeyDown = function() return false end
	end)
	local cas = serviceCache.ContextActionService or softInst("ContextActionService", "ContextActionService")
	serviceCache.ContextActionService = cas
	pcall(function()
		cas.GetAllBoundActionInfo = function() return {} end
	end)
	local ss = serviceCache.SoundService or softInst("SoundService", "SoundService")
	serviceCache.SoundService = ss
	pcall(function() ss.RolloffScale = 1 end)
	local li = serviceCache.Lighting or softInst("Lighting", "Lighting")
	serviceCache.Lighting = li
	pcall(function()
		li.ClockTime = 14
		li.Brightness = 2
	end)
	local hs = serviceCache.HttpService or softInst("HttpService", "HttpService")
	serviceCache.HttpService = hs
	pcall(function() hs.HttpEnabled = true end)
	local tw = serviceCache.TweenService or softInst("TweenService", "TweenService")
	serviceCache.TweenService = tw
	pcall(function()
		tw.GetValue = function() return 0.5 end
	end)
	local cp = serviceCache.ContentProvider or softInst("ContentProvider", "ContentProvider")
	serviceCache.ContentProvider = cp
	pcall(function()
		cp.GetRequestQueueSize = function() return 0 end
	end)
	local cam = softInst("Camera", "Camera")
	pcall(function()
		serviceCache.Workspace.CurrentCamera = cam
		cam.ClassName = "Camera"
		cam.CFrame = { Position = { X = 0, Y = 0, Z = 0 } }
	end)
	pcall(function()
		serviceCache.Players.GetPlayerByUserId = function(_, id)
			if id == 1 then return lp end
			return nil
		end
	end)
end

local env = {}
env.game = game
env.Game = game
-- WRD env-detect scripts probe these constantly
do
	local function setProp(o, k, v)
		if type(o) == "table" then
			rawset(o, k, v)
		end
	end
	setProp(game, "JobId", "00000000-0000-0000-0000-000000000000")
	setProp(game, "PlaceId", 0)
	setProp(game, "GameId", 0)
	setProp(game, "PlaceVersion", 1)
	setProp(game, "CreatorId", 0)
	setProp(game, "CreatorType", "User")
	setProp(game, "ClassName", "DataModel")
	setProp(game, "Name", "Game")
	if serviceCache.Workspace then
		setProp(serviceCache.Workspace, "ClassName", "Workspace")
		setProp(serviceCache.Workspace, "Name", "Workspace")
		setProp(serviceCache.Workspace, "Gravity", 196.2)
		setProp(serviceCache.Workspace, "DistributedGameTime", 0)
		setProp(serviceCache.Workspace, "StreamingEnabled", false)
	end
	if serviceCache.Players then
		setProp(serviceCache.Players, "ClassName", "Players")
	end
	if serviceCache.LocalPlayer then
		setProp(serviceCache.LocalPlayer, "UserId", 1)
		setProp(serviceCache.LocalPlayer, "DisplayName", "Player")
		setProp(serviceCache.LocalPlayer, "Name", "Player")
		setProp(serviceCache.LocalPlayer, "ClassName", "Player")
	end
end
env.workspace = serviceCache.Workspace
env.Workspace = serviceCache.Workspace
env.Instance = { new = function(c, parent)
	local o = softInst(c, c)
	if parent then o.Parent = parent end
	return o
end }
env.UDim2 = {
	new = function(a,b,c,d) return { X = { Scale = a or 0, Offset = b or 0 }, Y = { Scale = c or 0, Offset = d or 0 } } end,
	fromScale = function(x,y) return env.UDim2.new(x,0,y,0) end,
	fromOffset = function(x,y) return env.UDim2.new(0,x,0,y) end,
}
env.UDim = { new = function(s,o) return { Scale = s or 0, Offset = o or 0 } end }
env.Vector2 = { new = function(x,y) return { X = x or 0, Y = y or 0 } end, zero = { X = 0, Y = 0 }, one = { X = 1, Y = 1 } }
env.Vector3 = { new = function(x,y,z) return { X = x or 0, Y = y or 0, Z = z or 0 } end, zero = { X = 0, Y = 0, Z = 0 }, one = { X = 1, Y = 1, Z = 1 } }
env.CFrame = { new = function() return { Position = { X = 0, Y = 0, Z = 0 } } end, Angles = function() return {} end, identity = {} }
env.Color3 = {
	new = function(r,g,b) return { R = r or 0, G = g or 0, B = b or 0 } end,
	fromRGB = function(r,g,b) return { R = (r or 0)/255, G = (g or 0)/255, B = (b or 0)/255 } end,
	fromHSV = function(h,s,v) return { R = h or 0, G = s or 0, B = v or 0 } end,
	fromHex = function() return { R = 1, G = 1, B = 1 } end,
}
env.BrickColor = { new = function(n) return { Name = tostring(n), Color = env.Color3.new(1,1,1) } end }
env.Ray = { new = function(o,d) return { Origin = o, Direction = d } end }
env.Region3 = { new = function() return {} end }
env.Rect = { new = function() return {} end }
env.NumberSequence = { new = function() return {} end }
env.NumberRange = { new = function(a,b) return { Min = a or 0, Max = b or a or 0 } end }
env.ColorSequence = { new = function() return {} end }
env.TweenInfo = { new = function(t) return { Time = t or 1 } end }
env.Font = { new = function() return {} end, fromEnum = function(e) return e end }
env.Random = { new = function()
	return {
		NextNumber = function(_,a,b) return ((a or 0)+(b or 1))*0.5 end,
		NextInteger = function(_,a,b) return a or 1 end,
	}
end }
env.DateTime = {
	now = function() return { UnixTimestamp = os.time() } end,
	fromUnixTimestamp = function(t) return { UnixTimestamp = t or 0 } end,
}
env.Enum = setmetatable({}, {
	__index = function(_, k)
		-- official enum names available; unknown still works
		return setmetatable({ Name = k }, {
			__index = function(_, k2) return { Name = k2, EnumType = k, Value = 0 } end,
			__tostring = function() return "Enum." .. tostring(k) end,
		})
	end,
})
-- touch seed so Enum.KeyCode etc. exist when pairs/next used
pcall(function()
	for name in pairs(ALL_ENUM_NAMES or {}) do
		local _ = env.Enum[name]
	end
end)
env.Axes = { new = function() return {} end }
env.Faces = { new = function() return {} end }
env.OverlapParams = { new = function() return { FilterDescendantsInstances = {}, MaxParts = math.huge } end }
env.RaycastParams = { new = function() return { FilterDescendantsInstances = {}, CollisionGroup = "Default" } end }
env.CatalogSearchParams = { new = function() return {} end }
env.PathWaypoint = { new = function() return {} end }
env.PhysicalProperties = { new = function() return {} end }

env.Path2DControlPoint = env.Path2DControlPoint or { new = function(p,a,b) return {Position=p,LeftTangent=a,RightTangent=b} end }
env.SharedTable = env.SharedTable or { new = function(t) return t or {} end }
env.Content = env.Content or { fromUri = function(u) return tostring(u) end, fromAssetId = function(id) return "rbxassetid://"..tostring(id) end }
env.SecurityCapabilities = env.SecurityCapabilities or { new = function() return {} end }
env.Vector2int16 = env.Vector2int16 or { new = function(x,y) return {X=x or 0,Y=y or 0} end }
env.Vector3int16 = env.Vector3int16 or { new = function(x,y,z) return {X=x or 0,Y=y or 0,Z=z or 0} end }
env.ColorSequenceKeypoint = env.ColorSequenceKeypoint or { new = function(t,c) return {Time=t or 0,Value=c} end }
env.NumberSequenceKeypoint = env.NumberSequenceKeypoint or { new = function(t,v,e) return {Time=t or 0,Value=v or 0,Envelope=e or 0} end }
env.FloatCurveKey = env.FloatCurveKey or { new = function() return {} end }
env.RotationCurveKey = env.RotationCurveKey or { new = function() return {} end }
env.DockWidgetPluginGuiInfo = env.DockWidgetPluginGuiInfo or { new = function() return {} end }
env.Region3int16 = env.Region3int16 or { new = function() return {} end }

env.string = setmetatable({
	char = function(...)
		if dumpCheck() then return "" end
		local n = select("#", ...)
		if n == 1 then
			local b = tonumber((...))
			if b and b >= 0 and b <= 255 then
				charBuf[#charBuf + 1] = b
				if #charBuf >= 512 then flushChar() end
				return hostChar(b)
			end
		end
		flushChar()
		local r = hostChar(...)
		if type(r) == "string" then emit("string.char", r) end
		return r
	end,
	format = function(fmt, ...)
		flushChar()
		local ok, r = pcall(hostFormat, fmt, ...)
		if not ok then error(r, 2) end
		if type(r) == "string" then emit("string.format", r) end
		return r
	end,
	gsub = function(s, pat, repl, n)
		flushChar()
		local r, c = hostGsub(s, pat, repl, n)
		if type(r) == "string" and r ~= s then emit("string.gsub", r) end
		return r, c
	end,
	rep = function(s, n)
		local r = hostRep(s, n)
		if type(r) == "string" and #r >= 1 then emit("string.rep", r) end
		return r
	end,
	sub = function(s, i, j)
		local r = hostSub(s, i, j)
		if type(r) == "string" and #r >= 1 then emit("string.sub", r) end
		return r
	end,
	byte = function(s, i, j)
		return hostByte(s, i, j)
	end,
	len = function(s)
		return #tostring(s or "")
	end,
	lower = function(s)
		local r = string.lower(s)
		if r ~= s then emit("string.lower", r) end
		return r
	end,
	upper = function(s)
		local r = string.upper(s)
		if r ~= s then emit("string.upper", r) end
		return r
	end,
	reverse = function(s)
		local r = string.reverse(s)
		emit("string.reverse", r)
		return r
	end,
	-- pattern APIs that yield / return strings
	match = function(s, pat, init)
		local results = { string.match(s, pat, init) }
		for _, v in ipairs(results) do
			if type(v) == "string" and #v >= 1 then emit("string.match", v) end
		end
		return table.unpack(results)
	end,
	find = function(s, pat, init, plain)
		local results = { string.find(s, pat, init, plain) }
		for _, v in ipairs(results) do
			if type(v) == "string" and #v >= 1 then emit("string.find:cap", v) end
		end
		return table.unpack(results)
	end,
	gmatch = function(s, pat)
		local iter = string.gmatch(s, pat)
		return function()
			local results = { iter() }
			if results[1] == nil then return end
			for _, v in ipairs(results) do
				if type(v) == "string" and #v >= 1 then emit("string.gmatch", v) end
			end
			return table.unpack(results)
		end
	end,
	split = function(s, sep)
		local r = string.split(s, sep)
		if type(r) == "table" then
			for _, part in ipairs(r) do
				if type(part) == "string" and #part >= 1 then emit("string.split", part) end
			end
		end
		return r
	end,
	pack = function(...)
		local ok, r = pcall(string.pack, ...)
		if ok and type(r) == "string" then emit("string.pack", r) end
		if ok then return r end
		error(r, 2)
	end,
	packsize = function(fmt)
		return string.packsize(fmt)
	end,
	unpack = function(fmt, s, pos)
		if type(s) == "string" and #s >= 1 then emit("string.unpack:src", s) end
		local results = { pcall(string.unpack, fmt, s, pos) }
		if not results[1] and type(s) == "string" and type(fmt) == "string" then
			-- V1Dumper-style: pad short buffers so VM does not die
			local okS, need = pcall(string.packsize, fmt)
			if okS and type(need) == "number" then
				local start = tonumber(pos) or 1
				local avail = #s - start + 1
				if avail < need then
					local pad = string.rep("\0", need - math.max(avail, 0))
					-- fix: use real null
				end
			end
			local start = tonumber(pos) or 1
			local okS, need = pcall(string.packsize, fmt)
			if okS and type(need) == "number" then
				local avail = #s - start + 1
				if avail < need then
					local padded = s .. string.rep(string.char(0), need - math.max(avail, 0))
					results = { pcall(string.unpack, fmt, padded, pos) }
				end
			end
		end
		if not results[1] then
			-- soft fail: return nils instead of killing VM
			return nil, pos or 1
		end
		for i = 2, #results do
			if type(results[i]) == "string" and #results[i] >= 1 then
				emit("string.unpack", results[i])
			end
		end
		return table.unpack(results, 2)
	end,
}, { __index = string })

env.table = setmetatable({
	concat = function(list, sep, i, j)
		flushChar()
		local r = hostConcat(list, sep, i, j)
		if type(r) == "string" then
			emit("table.concat", r)
			-- force-keep detect / payload style lines even if filtered elsewhere
			if string.find(r, "DETECT", 1, true) or string.find(r, "JobId", 1, true)
				or string.find(r, "PAYLOAD", 1, true) or string.find(r, "Detection", 1, true) then
				local key = r
				if not seen[key] then
					seen[key] = true
					emitIndex += 1
					lines[#lines + 1] = string.format("[%d] = %s", emitIndex, r)
				end
			end
		end
		return r
	end,
	insert = function(list, pos, val)
		if val == nil then val = pos; pos = #list + 1 end
		if type(val) == "string" and #val >= 1 then emit("table.insert", val) end
		return table.insert(list, pos, val)
	end,
}, { __index = table })

if type(utf8) == "table" then
	env.utf8 = setmetatable({
		char = function(...)
			local n = select("#", ...)
			if n == 1 then
				local cp = tonumber((...))
				if cp then
					utf8Buf[#utf8Buf + 1] = cp
					if #utf8Buf >= 256 then flushUtf8() end
					return utf8.char(cp)
				end
			end
			flushUtf8()
			local r = utf8.char(...)
			if type(r) == "string" then emit("utf8.char", r) end
			return r
		end,
	}, { __index = utf8 })
else
	env.utf8 = utf8
end

if type(buffer) == "table" then
	local hostBuf = buffer
	local _bops = 0
	local function btick()
		_bops = _bops + 1
		if _bops % 256 == 0 and os.clock() - started > BUDGET then error("budget", 0) end
	end
	env.buffer = setmetatable({
		create = function(...)
			btick()
			return hostBuf.create(...)
		end,
		fromstring = function(s)
			if type(s) == "string" then emit("buffer.fromstring", s) end
			return hostBuf.fromstring(s)
		end,
		tostring = function(b)
			local r = hostBuf.tostring(b)
			if type(r) == "string" and #r >= 1 then
				emit("buffer.tostring", r)
				-- VM often dumps const pool names via buffer.tostring
				if #r >= 2 and #r <= 48 and string.match(r, "^[%a_][%w_]*$") then
					emit("bytecode.const", r)
				end
			end
			return r
		end,
		readstring = function(b, offset, len)
			btick()
			local r = hostBuf.readstring(b, offset, len)
			if type(r) == "string" and #r >= 1 then emit("buffer.readstring", r) end
			return r
		end,
		writestring = function(b, offset, s, ...)
			if type(s) == "string" then emit("buffer.writestring", s) end
			return hostBuf.writestring(b, offset, s, ...)
		end,
		readu8 = function(...)
			btick()
			return hostBuf.readu8(...)
		end,
		readi8 = function(...)
			btick()
			return hostBuf.readi8(...)
		end,
		readu16 = function(...)
			btick()
			return hostBuf.readu16(...)
		end,
		readu32 = function(...)
			btick()
			return hostBuf.readu32(...)
		end,
		len = function(b)
			return hostBuf.len(b)
		end,
		copy = function(...)
			return hostBuf.copy(...)
		end,
		fill = function(...)
			return hostBuf.fill(...)
		end,
	}, { __index = hostBuf })
else
	env.buffer = buffer
end

-- common executor crypto helpers (UNC / Synapse / Fluxus / Script-Ware)
local function b64encode(data)
	local b = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	local s = tostring(data or "")
	emit("base64.encode:src", s)
	local out = {}
	for i = 1, #s, 3 do
		local a, c, d = string.byte(s, i, i + 2)
		a = a or 0; c = c or 0; d = d or 0
		local n = a * 65536 + c * 256 + d
		local n1 = math.floor(n / 262144) % 64
		local n2 = math.floor(n / 4096) % 64
		local n3 = math.floor(n / 64) % 64
		local n4 = n % 64
		out[#out + 1] = string.sub(b, n1 + 1, n1 + 1)
		out[#out + 1] = string.sub(b, n2 + 1, n2 + 1)
		out[#out + 1] = (i + 1 <= #s) and string.sub(b, n3 + 1, n3 + 1) or "="
		out[#out + 1] = (i + 2 <= #s) and string.sub(b, n4 + 1, n4 + 1) or "="
	end
	local r = table.concat(out)
	emit("base64.encode", r)
	return r
end
local function b64decode(data)
	local b = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	local s = tostring(data or ""):gsub("%s+", "")
	emit("base64.decode:src", s)
	local lookup = {}
	for i = 1, #b do lookup[string.sub(b, i, i)] = i - 1 end
	local out = {}
	local buf, nbits = 0, 0
	for i = 1, #s do
		local ch = string.sub(s, i, i)
		if ch ~= "=" then
			local v = lookup[ch]
			if v then
				buf = buf * 64 + v
				nbits = nbits + 6
				if nbits >= 8 then
					nbits = nbits - 8
					out[#out + 1] = string.char(math.floor(buf / (2 ^ nbits)) % 256)
					buf = buf % (2 ^ nbits)
				end
			end
		end
	end
	local r = table.concat(out)
	emit("base64.decode", r)
	return r
end
local function emitPassthrough(tag, data)
	data = tostring(data or "")
	emit(tag, data)
	return data
end
local cryptBase64 = { encode = b64encode, decode = b64decode }
local cryptTbl = {
	base64encode = b64encode,
	base64decode = b64decode,
	base64_encode = b64encode,
	base64_decode = b64decode,
	base64 = cryptBase64,
	encode = function(s) return emitPassthrough("crypt.encode", s) end,
	decode = function(s) return emitPassthrough("crypt.decode", s) end,
	hash = function(s, _)
		s = tostring(s or "")
		emit("crypt.hash:src", s)
		return "0"
	end,
	generatekey = function() return "00000000000000000000000000000000" end,
	generatebytes = function(n)
		n = tonumber(n) or 16
		return string.rep("\0", math.clamp(n, 0, 1024))
	end,
	random = function(n)
		n = tonumber(n) or 16
		return string.rep("A", math.clamp(n, 0, 1024))
	end,
	derive = function(v, len)
		emit("crypt.derive:src", tostring(v or ""))
		return string.rep("0", tonumber(len) or 32)
	end,
	encrypt = function(data, key, iv, mode)
		data = tostring(data or "")
		emit("crypt.encrypt:src", data)
		return b64encode(data)
	end,
	decrypt = function(data, key, iv, mode)
		data = tostring(data or "")
		emit("crypt.decrypt:src", data)
		local ok, r = pcall(b64decode, data)
		return ok and r or data
	end,
	custom = {
		encrypt = function(cipher, data, key, iv)
			data = tostring(data or "")
			emit("crypt.custom.encrypt:src", data)
			return b64encode(data)
		end,
		decrypt = function(cipher, data, key, iv)
			data = tostring(data or "")
			emit("crypt.custom.decrypt:src", data)
			local ok, r = pcall(b64decode, data)
			return ok and r or data
		end,
		hash = function(data, algo)
			data = tostring(data or "")
			emit("crypt.custom.hash:src", data)
			return "0"
		end,
	},
}
env.crypt = cryptTbl
env.crypto = cryptTbl
env.syn = env.syn or {}
env.syn.crypt = cryptTbl
env.base64 = cryptBase64
env.base64_encode = b64encode
env.base64_decode = b64decode
env.base64encode = b64encode
env.base64decode = b64decode
-- flat UNC aliases
env.crypt_base64encode = b64encode
env.crypt_base64decode = b64decode


-- Hook bit32 (VM XOR loops); periodic budget
do
	local hb = bit32
	local _ops = 0
	if type(hb) == "table" then
		env.bit32 = setmetatable({}, {
			__index = function(_, k)
				local f = rawget(hb, k)
				if type(f) ~= "function" then return f end
				return function(...)
					_ops = _ops + 1
					if _ops % 512 == 0 and os.clock() - started > BUDGET then error("budget", 0) end
					return f(...)
				end
			end,
		})
		env.bit = env.bit32
	end
end
env.math = math
env.bit32 = bit32

-- SOFT_ARITH_WXZ: WeAreDevs / heavy VM often does n+nil / nil^n
do
	local function softN(v)
		local t = type(v)
		if t == "number" then return v end
		if t == "nil" then return 0 end
		if t == "boolean" then return v and 1 or 0 end
		if t == "string" then
			local n = tonumber(v)
			return n or 0
		end
		return 0
	end
	local _add = function(a, b) return softN(a) + softN(b) end
	local _sub = function(a, b) return softN(a) - softN(b) end
	local _mul = function(a, b) return softN(a) * softN(b) end
	local _div = function(a, b)
		b = softN(b)
		if b == 0 then return 0 end
		return softN(a) / b
	end
	local _mod = function(a, b)
		b = softN(b)
		if b == 0 then return 0 end
		return softN(a) % b
	end
	local _pow = function(a, b)
		a, b = softN(a), softN(b)
		if b ~= b or a ~= a then return 0 end -- nan
		if b > 64 or b < -64 then return 0 end -- avoid huge
		local ok, r = pcall(function() return a ^ b end)
		return ok and r or 0
	end
	local _unm = function(a) return -softN(a) end
	-- Wrap number metatable if possible (Lune may not allow)
	pcall(function()
		local mt = getmetatable(0)
		if type(mt) ~= "table" then
			-- create proxy number helpers used by some VMs via setmetatable tricks
		end
	end)
	env.__soft_add = _add
	env.__soft_sub = _sub
	env.__soft_mul = _mul
	env.__soft_div = _div
	env.__soft_mod = _mod
	env.__soft_pow = _pow
end


env.bit = bit32
-- Virtual clock (V1Dumper-style): task.wait advances guest time + fires "frame" hooks
do
	local realClock = os.clock
	local realTime = os.time
	local realDate = os.date
	local vclock = 0
	local bootHost = realClock()
	local bootUnix = realTime()
	local cpuAccum = 0
	local busyStreak = 0
	local lastHost = 0
	local frameHandlers = {}

	local function hostElapsed()
		local h = realClock() - bootHost
		if h < 0 then h = 0 end
		return h
	end

	local function fireFrames(dt)
		for i = 1, #frameHandlers do
			pcall(frameHandlers[i], dt)
		end
	end

	local function advance(step)
		step = tonumber(step) or 0
		if step < 0 then step = 0 end
		if step == 0 then step = 0.00001 end
		-- ~60fps frames for Heartbeat-style checks
		local n = math.max(1, math.floor(step * 60 + 0.5))
		if n > 120 then n = 120 end
		local dt = step / n
		for i = 1, n do
			vclock = vclock + dt
			fireFrames(dt)
		end
		return step
	end

	env._dumpAdvance = advance
	env._dumpOnFrame = function(fn)
		if type(fn) == "function" then frameHandlers[#frameHandlers + 1] = fn end
	end

	env.os = {
		clock = function()
			local host = hostElapsed()
			local dh = host - lastHost
			lastHost = host
			if dh < 0 then dh = 0 end
			if dh < 0.001 then
				busyStreak = busyStreak + 1
				cpuAccum = cpuAccum + 0.05 * math.min(1 + busyStreak / 5, 20)
			else
				busyStreak = 0
				cpuAccum = cpuAccum + dh * 0.015
			end
			return vclock + cpuAccum
		end,
		time = function(t)
			if t ~= nil then return realTime(t) end
			return math.floor(bootUnix + vclock + hostElapsed())
		end,
		date = function(fmt, t)
			local ts = t or (bootUnix + vclock + hostElapsed())
			return realDate(fmt, ts)
		end,
		difftime = os.difftime,
	}
	env.tick = function() return bootUnix + vclock + hostElapsed() end
	env.time = function() return vclock + hostElapsed() end
	env.elapsedTime = env.time

	env.coroutine = coroutine
	env.debug = debug or {}
	env.task = {
		wait = function(t)
			if realClock() - started > BUDGET then error("budget", 0) end
			local s = tonumber(t)
			if s == nil then s = 0 end
			if s < 0 then s = 0 end
			if s == 0 then s = 0.00001 end
			return advance(s)
		end,
		spawn = function(f, ...)
			if type(f) == "function" then
				local a = table.pack(...)
				pcall(function() f(table.unpack(a, 1, a.n)) end)
			elseif type(f) == "thread" then
				pcall(coroutine.resume, f, ...)
			end
		end,
		defer = function(f, ...)
			if type(f) == "function" then pcall(f, ...) end
		end,
		delay = function(d, f, ...)
			if type(f) == "function" then
				advance(tonumber(d) or 0)
				pcall(f, ...)
			end
		end,
		synchronize = function(f) if type(f) == "function" then return f() end end,
		desynchronize = function() end,
		cancel = function() end,
	}
end
env.print = function(...)
	for i = 1, select("#", ...) do
		local v = select(i, ...)
		local s = type(v) == "string" and v or tostring(v)
		if type(s) == "string" and #s >= 1 then
			emit("print", s)
			if string.find(s, "DETECT", 1, true) or string.find(s, "PAYLOAD", 1, true)
				or string.find(s, "Detection", 1, true) or string.find(s, "Passed", 1, true) then
				if not seen[s] then
					seen[s] = true
					emitIndex += 1
					lines[#lines + 1] = string.format("[%d] = %s", emitIndex, s)
				end
			end
		end
	end
end
env.warn = env.print
env.error = function(msg, level)
	local t = tostring(msg or "")
	local low = string.lower(t)
	if t == "budget" or low == "budget" or string.find(low, "budget", 1, true) then
		error("budget", 0)
	end
	-- Wide AT / packer bypass (V1Dumper-inspired) — keep generic nil for loop exit
	for _, p in ipairs({
		"antitamper", "anti-tamper", "anti tamper", "tamper detected", "tamper",
		"dark triad", "dtc", "00fuscator", "sec ::", "integrity check",
		"protected", "environment integrity", "deobf", "8xms", "luaq",
		"obscura", "wynfuscate", "catph", "galactic", "nev ", "blocked by",
		"non-resumable", "dead coroutine", "cannot resume", "cannot yield across",
		"level out of range", "guf", "looking at you", "load player",
	}) do
		if string.find(low, p, 1, true) then
			return nil
		end
	end
	return error(msg, level or 2)
end
env.assert = function(cond, msg)
	if not cond then
		local t = tostring(msg or "assertion failed")
		local low = string.lower(t)
		if string.find(low, "tamper", 1, true) or string.find(low, "detect", 1, true) then
			return cond
		end
		error(msg or "assertion failed!", 2)
	end
	return cond
end
env.pcall = pcall
env.xpcall = xpcall
env.type = type
env.typeof = function(v)
	if type(v) == "table" and type(v.ClassName) == "string" then return "Instance" end
	return type(v)
end
env.tostring = function(v)
	local r = tostring(v)
	-- only log when converting non-string useful values, or always log short results
	if type(r) == "string" and #r >= 1 and #r <= 500 then
		if type(v) == "string" then
			emit("tostring", r)
		elseif type(v) == "number" or type(v) == "boolean" then
			-- skip pure number tostring noise unless long
			if #r >= 4 then emit("tostring", r) end
		else
			emit("tostring", r)
		end
	end
	return r
end
env.tonumber = tonumber
env.pairs = pairs
env.ipairs = ipairs
env.next = next
env.select = function(idx, ...)
	local n = select("#", ...)
	for i = 1, n do
		local v = select(i, ...)
		if type(v) == "string" and #v >= 2 and #v <= 80 then emit("vm:select", v) end
	end
	return select(idx, ...)
end
env.unpack = table.unpack or unpack
env.rawget = function(t, k)
	if type(k) == "string" and #k >= 2 then emit("vm:rawget", k) end
	return rawget(t, k)
end
env.rawset = function(t, k, v)
	if type(k) == "string" and #k >= 2 then emit("vm:rawset:key", k) end
	if type(v) == "string" and #v >= 1 then emit("vm:rawset:val", v) end
	return rawset(t, k, v)
end
env.rawequal = rawequal
env.rawlen = rawlen or function(t) return #t end
env.setmetatable = setmetatable
env.getmetatable = getmetatable
env._G = env
env.shared = {}
env.tick = os.clock
env.time = os.clock
env.wait = env.task.wait
env.spawn = env.task.spawn
env.delay = env.task.delay
env.require = function()
	return setmetatable({}, { __index = function() return function() return nil end end })
end
env.getfenv = function() return env end
env.setfenv = function() end
do
	local _lsDepth = 0
	local _chunks = {}
	env.loadstring = function(code)
		if type(code) == "string" then
			if string.match(code, "^https?://") then emit("loadstring-url", code) end
			if #code >= 1 then
				emit("loadstring-src", string.sub(code, 1, 8000))
				emit("bytecode.const", "loadstring")
				pcall(harvestCode, code, "ls")
				-- nested bytecode.const: lib.member + known tokens
				for lib, mem in string.gmatch(code, "([%a_][%w_]*)%.([%a_][%w_]*)") do
					if (lib == "buffer" or lib == "bit32" or lib == "string" or lib == "table"
						or lib == "coroutine" or lib == "debug" or lib == "utf8" or lib == "math"
						or lib == "task" or lib == "Instance" or lib == "game") and #mem >= 2 then
						emit("bytecode.const", lib)
						emit("bytecode.const", mem)
					end
				end
				_chunks[#_chunks + 1] = code
			end
		end
		local src = tostring(code or "")
		local ok, fn = pcall(luau.load, src, {
			debugName = "ls",
			environment = env,
		})
		if not ok or type(fn) ~= "function" then
			return function() end
		end
		return function(...)
			if os.clock() - started > BUDGET then return nil end
			if _lsDepth >= 4 then return nil end
			_lsDepth = _lsDepth + 1
			local r = table.pack(pcall(fn, ...))
			_lsDepth = _lsDepth - 1
			if not r[1] then return nil end
			return table.unpack(r, 2, r.n)
		end
	end
	env.load = env.loadstring
end

env.newproxy = function() return setmetatable({}, {}) end
env.gcinfo = function() return 0 end
env.collectgarbage = function() return 0 end
env.ypcall = pcall
env.elapsedTime = os.clock
env.PluginManager = function() return softInst("PluginManager") end
env.settings = function() return softInst("GlobalSettings") end
env.UserSettings = function() return softInst("UserSettings") end



-- Lupro-strength executor / env stubs (so VM/loadstring paths keep running)
env.getgenv = function() return env end
env.getrenv = function() return env end
env.getfenv = function() return env end
env.setfenv = function() return env end
env.getrawmetatable = getmetatable
env.setrawmetatable = setmetatable
env.newcclosure = function(f) return f end
env.iscclosure = function() return false end
env.islclosure = function() return true end
env.checkcaller = function() return true end
env.clonefunction = function(f) return f end
env.hookfunction = function(a, b) return a end
env.hookmetamethod = function(t, k, v) return function() end end
env.getnamecallmethod = function() return "" end
env.getcallingscript = function() return nil end
env.identifyexecutor = function() return "DumpString", "1.0" end
env.getexecutorname = env.identifyexecutor
env.lp = function() return serviceCache.LocalPlayer end
env.game = env.game
env.HttpGet = function(url)
	if type(url) == "string" then emit("HttpGet", url) end
	return ""
end
env.HttpGetAsync = env.HttpGet
env.httpget = env.HttpGet
if env.game then
	-- softInst already handles GetService; also allow game:HttpGet
end
env.request = function(opts)
	if type(opts) == "table" and type(opts.Url) == "string" then emit("request.Url", opts.Url) end
	return { Success = true, StatusCode = 200, Body = "", Headers = {} }
end
env.http = { request = env.request }
env.syn = env.syn or {}
env.syn.request = env.request
env.fluxus = { request = env.request }
env.krnl = { request = env.request }
env.setclipboard = function(s) if type(s)=="string" then emit("clipboard", s) end end
env.toclipboard = env.setclipboard
env.writefile = function(path, data)
	if type(path) == "string" then emit("writefile:path", path) end
	if type(data) == "string" and #data >= 1 then emit("writefile:data", string.sub(data, 1, 2000)) end
end
env.readfile = function() return "" end
env.isfile = function() return false end
env.isfolder = function() return false end
env.makefolder = function() end
env.listfiles = function() return {} end
env.appendfile = env.writefile
env.delfile = function() end
env.gethui = function() return softInst("Folder", "HUD") end
env.getconnections = function() return {} end
env.firesignal = function() end
env.fireclickdetector = function() end
env.fireproximityprompt = function() end
env.mousemoverel = function() end
env.mouse1click = function() end


-- Overlay full RobloxFidelity surface + Clock + logged setmetatable
if type(Fidelity) == "table" then
	for _, n in ipairs({
		"Color3","UDim","UDim2","Rect","NumberRange",
		"NumberSequence","ColorSequence","Path2DControlPoint","RaycastParams","OverlapParams",
		"Random","BrickColor","TweenInfo","Axes","Faces","DateTime","Ray","Region3",
		"PhysicalProperties","Font","CatalogSearchParams",
	}) do
		if type(Fidelity[n]) == "table" or type(Fidelity[n]) == "function" then
			env[n] = Fidelity[n]
		end
	end
	if type(Fidelity.JsonEncode) == "function" then
		env.JSONEncode = Fidelity.JsonEncode
		env.JSONDecode = Fidelity.JsonDecode
		env.HttpService = env.HttpService or {}
		-- soft table for encode
		local hs = { JSONEncode = Fidelity.JsonEncode, JSONDecode = Fidelity.JsonDecode,
			GenerateGUID = function() return "00000000-0000-0000-0000-000000000000" end }
		env.HttpService = setmetatable(hs, { __index = function() return function() end end })
	end
	if type(Fidelity.EnumValues) == "table" then
		env.Enum = setmetatable({}, {
			__index = function(_, k)
				local items = Fidelity.EnumValues[k]
				if type(items) == "table" then
					return setmetatable({ Name = k }, {
						__index = function(_, k2)
							local v = items[k2]
							return { Name = k2, EnumType = k, Value = type(v) == "number" and v or 0 }
						end,
					})
				end
				return setmetatable({ Name = k }, {
					__index = function(_, k2) return { Name = k2, EnumType = k, Value = 0 } end,
				})
			end,
		})
	end
	-- Fidelity.Clock bridged to dump virtual clock
	if type(Fidelity.Clock) ~= "table" then
		Fidelity.Clock = { PhysicsTime = 0, StepSeconds = 1/60, LastDelta = 1/60, Tweens = {} }
	end
	Fidelity.Clock.ElapsedTime = function()
		return (env.os and env.os.clock and env.os.clock()) or 0
	end
	Fidelity.Clock.Tick = function()
		return (env.tick and env.tick()) or os.time()
	end
	Fidelity.Clock.Step = function(s)
		s = tonumber(s) or (1/60)
		if type(env._dumpAdvance) == "function" then env._dumpAdvance(s) end
		Fidelity.Clock.LastDelta = s
		Fidelity.Clock.PhysicsTime = (Fidelity.Clock.PhysicsTime or 0) + s
		return s
	end
	-- Budget-wrapped setmetatable: every metamethod ticks the clock (XHider-style VMs)
	do
		local hostSet = setmetatable
		local function wrapMt(mt)
			if type(mt) ~= "table" then return mt end
			local w = {}
			for k, v in pairs(mt) do
				if type(v) == "function" then
					local fn = v
					local key = k
					w[k] = function(...)
						if dumpCheck() then
							-- soft-kill: pcall-safe, breaks arithmetic loops
							if key == "__add" or key == "__sub" or key == "__mul" or key == "__div"
								or key == "__pow" or key == "__mod" then
								return 0
							end
							if key == "__eq" or key == "__lt" or key == "__le" then
								return false
							end
							if key == "__len" then return 0 end
							if key == "__concat" then return "" end
							if key == "__tostring" then return "" end
							if key == "__call" then return end
							return nil
						end
						if key == "__index" then
							local idx = select(2, ...)
							if type(idx) == "string" and #idx >= 2 then
								emit("vm:mtindex", idx)
							end
						end
						return fn(...)
					end
				else
					w[k] = v
				end
			end
			return w
		end
		env.setmetatable = function(obj, mt)
			return hostSet(obj, wrapMt(mt))
		end
	end
end -- Fidelity overlay

-- ========== GENERIC VM HOOK LAYER ==========
-- Works for WRD / Luraph-style / IronBrew-like / any setmetatable VM:
-- 1) wrap every metatable method (budget + string harvest)
-- 2) numeric missing keys → 0 (register files)
-- 3) capture __index/__newindex/__call string traffic
-- 4) __reg() for rewritten register tables
do
	local hostSet = setmetatable
	local hostRawset = rawset
	local hostRawget = rawget

	local function safeCall(fn, ...)
		local pack = table.pack(pcall(fn, ...))
		if not pack[1] then
			local err = tostring(pack[2] or "")
			if string.find(err, "budget", 1, true) then
				error("budget", 0)
			end
			-- swallow VM metamethod errors so the outer loop can continue when possible
			return nil
		end
		return table.unpack(pack, 2, pack.n)
	end

	local function harvestVal(tag, v)
		if type(v) == "string" and #v >= 1 and #v < 8000 then
			emit(tag, v)
		elseif type(v) == "table" then
			-- shallow: array strings only
			local n = #v
			if n > 0 and n < 500 then
				for i = 1, n do
					local e = rawget(v, i)
					if type(e) == "string" and #e >= 1 then emit(tag .. ".arr", e) end
				end
			end
		end
	end

	local function wrapMt(mt)
		if type(mt) ~= "table" then return mt end
		-- already wrapped?
		if rawget(mt, "__wxz_wrapped") then return mt end
		local w = { __wxz_wrapped = true }
		local origIndex = mt.__index
		local origNew = mt.__newindex

		for k, v in pairs(mt) do
			if k ~= "__index" and k ~= "__newindex" and type(v) == "function" then
				local fn, key = v, k
				w[k] = function(...)
					if os.clock() - started > BUDGET then error("budget", 0) end
					local results = table.pack(pcall(fn, ...))
					if not results[1] then
						local err = tostring(results[2] or "")
						if string.find(err, "budget", 1, true) then error("budget", 0) end
						-- arithmetic-safe defaults for VM ops
						if key == "__add" or key == "__sub" or key == "__mul" or key == "__mod" or key == "__pow" then
							return 0
						end
						if key == "__div" then return 1 end
						if key == "__eq" or key == "__lt" or key == "__le" then return false end
						if key == "__len" then return 0 end
						if key == "__concat" then return "" end
						if key == "__tostring" then return "" end
						if key == "__call" then return end
						return nil
					end
					for i = 2, results.n do
						harvestVal("vm:" .. key, results[i])
					end
					return table.unpack(results, 2, results.n)
				end
			elseif k ~= "__index" and k ~= "__newindex" then
				w[k] = v
			end
		end

		w.__index = function(obj, key)
			if os.clock() - started > BUDGET then error("budget", 0) end
			if type(key) == "string" and #key >= 1 then emit("vm:idx", key) end
			local v
			if origIndex == nil then
				v = hostRawget(obj, key)
			elseif type(origIndex) == "function" then
				local ok, r = pcall(origIndex, obj, key)
				v = ok and r or nil
			elseif type(origIndex) == "table" then
				v = origIndex[key]
			end
			if v == nil and type(key) == "number" then
				return 0
			end
			harvestVal("vm:idxv", v)
			return v
		end

		w.__newindex = function(obj, key, val)
			if os.clock() - started > BUDGET then error("budget", 0) end
			if type(key) == "string" and #key >= 1 then emit("vm:newk", key) end
			harvestVal("vm:newv", val)
			if origNew == nil then
				hostRawset(obj, key, val)
			elseif type(origNew) == "function" then
				pcall(origNew, obj, key, val)
			else
				hostRawset(obj, key, val)
			end
		end

		return w
	end

	env.setmetatable = function(obj, mt)
		return hostSet(obj, wrapMt(mt))
	end
	env.getmetatable = getmetatable
	env.rawset = function(t, k, v)
		harvestVal("rawset", v)
		if type(k) == "string" then emit("rawset:k", k) end
		return hostRawset(t, k, v)
	end
	-- CRITICAL: rawget on register holes must not return nil (Luau 1+nil = hard error)
	env.rawget = function(t, k)
		local v = hostRawget(t, k)
		if v == nil and type(k) == "number" then
			return 0
		end
		harvestVal("rawget", v)
		return v
	end
	-- select() on sparse register packs
	local hostSelect = select
	env.select = function(i, ...)
		if i == "#" then return hostSelect("#", ...) end
		local n = hostSelect("#", ...)
		if type(i) == "number" and i >= 1 and i <= n then
			local v = hostSelect(i, ...)
			if v == nil then return 0 end
			return v
		end
		return hostSelect(i, ...)
	end
end

-- Safe arithmetic globals some VMs bind via getfenv
env.__add = function(a, b) return (tonumber(a) or 0) + (tonumber(b) or 0) end
env.__sub = function(a, b) return (tonumber(a) or 0) - (tonumber(b) or 0) end
env.__mul = function(a, b) return (tonumber(a) or 0) * (tonumber(b) or 0) end
env.__div = function(a, b)
	local d = tonumber(b) or 1
	if d == 0 then d = 1 end
	return (tonumber(a) or 0) / d
end


-- Arithmetic-safe soft value for missing globals / unknown services
local softProxy
softProxy = setmetatable({}, {
	__index = function(_, k)
		if type(k) == "string" and #k >= 2 then emit("soft:idx", k) end
		return softProxy
	end,
	__newindex = function(_, k, v)
		if type(v) == "string" and #v >= 1 then emit("soft:new", v) end
		if type(k) == "string" and #k >= 1 then emit("soft:newk", k) end
	end,
	__call = function(_, ...)
		for i = 1, select("#", ...) do
			local a = select(i, ...)
			if type(a) == "string" and #a >= 1 then emit("soft:call", a) end
		end
		return softProxy
	end,
	__add = function(a, b)
		return (tonumber(a) or 0) + (tonumber(b) or 0)
	end,
	__sub = function(a, b)
		return (tonumber(a) or 0) - (tonumber(b) or 0)
	end,
	__mul = function(a, b)
		return (tonumber(a) or 0) * (tonumber(b) or 0)
	end,
	__div = function(a, b)
		local d = tonumber(b) or 1
		if d == 0 then d = 1 end
		return (tonumber(a) or 0) / d
	end,
	__mod = function(a, b)
		local d = tonumber(b) or 1
		if d == 0 then d = 1 end
		return (tonumber(a) or 0) % d
	end,
	__pow = function(a, b)
		return (tonumber(a) or 0) ^ (tonumber(b) or 0)
	end,
	__unm = function(a)
		return -(tonumber(a) or 0)
	end,
	__eq = function() return false end,
	__lt = function() return false end,
	__le = function() return false end,
	__len = function() return 0 end,
	__concat = function(a, b)
		local sa = type(a) == "string" and a or tostring(a or "")
		local sb = type(b) == "string" and b or tostring(b or "")
		local r = sa .. sb
		if #r >= 1 then emit("soft:cat", r) end
		return r
	end,
	__tostring = function() return "" end,
})
local softTbl = softProxy

-- Register-file factory used by source transform of VM obfuscators
env.__n = function(v)
	local ty = type(v)
	if ty == "number" then return v end
	if ty == "string" then return tonumber(v) or 0 end
	return 0
end
env.__reg = function()
	return setmetatable({}, {
		__index = function(t, k)
			local v = rawget(t, k)
			if v ~= nil then return v end
			if type(k) == "number" then return 0 end
			if type(k) == "string" and #k >= 1 then emit("reg:idx", k) end
			return softProxy
		end,
		__newindex = function(t, k, v)
			-- WRD does W[i]=nil to free; keep 0 so later W[i]+n never sees nil
			if v == nil and type(k) == "number" then
				rawset(t, k, 0)
				return
			end
			rawset(t, k, v)
			if type(v) == "string" and #v >= 1 then emit("reg:new", v) end
			if type(k) == "string" and #k >= 1 then emit("reg:newk", k) end
		end,
	})
end

setmetatable(env, {
	__index = function(_, k)
		local v = rawget(_G, k)
		if v ~= nil then return v end
		if type(k) == "string" then return softProxy end
		return softProxy
	end,
})


local envKeys, envVals = {}, {}
for k, v in pairs(env) do
	if type(k) == "string" and string.match(k, "^[%a_][%w_]*$") then
		envKeys[#envKeys + 1] = k
		envVals[#envVals + 1] = v
	end
end
for i = 1, #envKeys do
	_G[envKeys[i]] = envVals[i]
end
_G._G = env





-- XHIDER_STATIC_DECODE: XHD ascii85 + per-file XOR keys (extracted, not hardcoded)
do
	local function xhAscii85(body)
		if type(body) ~= "string" or #body < 2 then return nil end
		local out = {}
		local i = 1
		local n = #body
		while i <= n do
			local remain = n - i + 1
			local f = remain >= 5 and 5 or remain
			if f < 2 then break end
			local W = 0
			if i + 4 > n then
				for F = 1, f do
					W = W * 0x55 + (string.byte(body, i + F - 1) - 0x21)
				end
				for _ = f + 1, 5 do
					W = W * 0x55 + 0x54
				end
			else
				for F = 0, 4 do
					W = W * 0x55 + (string.byte(body, i + F) - 0x21)
				end
			end
			local b0 = math.floor(W / 0x1000000) % 256
			local b1 = math.floor(W / 0x10000) % 256
			local b2 = math.floor(W / 0x100) % 256
			local b3 = W % 256
			if f == 5 then
				out[#out + 1] = string.char(b0, b1, b2, b3)
			elseif f == 4 then
				out[#out + 1] = string.char(b0, b1, b2)
			elseif f == 3 then
				out[#out + 1] = string.char(b0, b1)
			elseif f == 2 then
				out[#out + 1] = string.char(b0)
			end
			i = i + f
		end
		local r = table.concat(out)
		return #r > 0 and r or nil
	end

	local function xhInteresting(s)
		if type(s) ~= "string" or #s < 2 or #s > 4000 then return false end
		local good = 0
		for i = 1, #s do
			local b = string.byte(s, i)
			if (b >= 32 and b <= 126) or b == 9 or b == 10 then good += 1 end
		end
		return good >= math.max(2, math.floor(#s * 0.7))
	end

	local function xhWalk(buf, keys)
		local results = {}
		local pos = 1
		local guard = 0
		while pos + 3 <= #buf and guard < 8000 do
			guard += 1
			local b0 = bit32.bxor(string.byte(buf, pos), keys[1])
			local b1 = bit32.bxor(string.byte(buf, pos + 1), keys[2])
			local b2 = bit32.bxor(string.byte(buf, pos + 2), keys[3])
			local b3 = bit32.bxor(string.byte(buf, pos + 3), keys[4])
			local len = b0 + b1 * 256 + b2 * 65536 + b3 * 16777216
			pos += 4
			if len <= 0 or len > 20000 or pos + len - 1 > #buf then
				pos = pos - 3
			else
				local chars = table.create(len)
				for i = 1, len do
					local k = keys[((i - 1) % 4) + 1]
					chars[i] = string.char(bit32.bxor(string.byte(buf, pos + i - 1), k))
				end
				pos += len
				local s = table.concat(chars)
				if xhInteresting(s) then
					results[#results + 1] = s
				end
			end
		end
		return results
	end

	local function xhScore(list)
		local score = 0
		for _, s in ipairs(list) do
			score += #s
			if string.match(s, "^[%a_][%w_]*$") then score += 8 end
			if string.find(s, " ", 1, true) then score += 4 end
		end
		return score + #list * 3
	end

	-- Pull candidate 4-byte XOR keys from source (each XHider build differs)
	local function xhExtractKeysets(src)
		local keysets = {}
		local seen = {}
		local function add(a, b, c, d)
			if type(a) ~= "number" then return end
			a, b, c, d = a % 256, b % 256, c % 256, d % 256
			local k = string.format("%d.%d.%d.%d", a, b, c, d)
			if not seen[k] then
				seen[k] = true
				keysets[#keysets + 1] = { a, b, c, d }
			end
		end
		-- {0xAD;0xEF,0xD0;0xE4} / {0xAD, 0xEF, 0xD0, 0xE4}
		for a, b, c, d in string.gmatch(src, "0[xX](%x+)%s*[,;]%s*0[xX](%x+)%s*[,;]%s*0[xX](%x+)%s*[,;]%s*0[xX](%x+)") do
			add(tonumber(a, 16), tonumber(b, 16), tonumber(c, 16), tonumber(d, 16))
		end
		-- decimal quartets that look like key bytes
		for a, b, c, d in string.gmatch(src, "(%d+)%s*[,;]%s*(%d+)%s*[,;]%s*(%d+)%s*[,;]%s*(%d+)") do
			local na, nb, nc, nd = tonumber(a), tonumber(b), tonumber(c), tonumber(d)
			if na and nb and nc and nd and na < 256 and nb < 256 and nc < 256 and nd < 256 then
				if (na + nb + nc + nd) > 0 then
					add(na, nb, nc, nd)
				end
			end
		end
		-- folded expressions sometimes: no hex; leave empty if none
		if #keysets == 0 then
			-- last resort identity (no xor) + common legacy only as weak fallback
			add(0, 0, 0, 0)
		end
		return keysets
	end

	local function xhExtractPayload(src)
		local start = string.find(src, '"XHD:', 1, true)
		if not start then return nil end
		local parts = {}
		local pos = start
		local limit = math.min(#src, start + 120000)
		while pos <= limit do
			if string.sub(src, pos, pos) ~= '"' then
				if string.sub(src, pos, pos) == "}" then break end
				pos += 1
			else
				pos += 1
				local buf = {}
				while pos <= limit do
					local c = string.sub(src, pos, pos)
					if c == "\\" and pos < limit then
						local n = string.sub(src, pos + 1, pos + 1)
						if n == "n" then buf[#buf + 1] = "\n"; pos += 2
						elseif n == "r" then buf[#buf + 1] = "\r"; pos += 2
						elseif n == "t" then buf[#buf + 1] = "\t"; pos += 2
						elseif n == "\\" or n == '"' or n == "'" then buf[#buf + 1] = n; pos += 2
						else buf[#buf + 1] = n; pos += 2 end
					elseif c == '"' then
						pos += 1
						break
					else
						buf[#buf + 1] = c
						pos += 1
					end
				end
				parts[#parts + 1] = table.concat(buf)
				while pos <= limit do
					local ch = string.sub(src, pos, pos)
					if ch == " " or ch == "\t" or ch == "\n" or ch == "\r" or ch == "," or ch == ";" then
						pos += 1
					else
						break
					end
				end
				if string.sub(src, pos, pos) == "}" then break end
				if string.sub(src, pos, pos) ~= '"' then break end
			end
		end
		if #parts == 0 then return nil end
		local joined = table.concat(parts)
		if string.sub(joined, 1, 4) == "XHD:" then
			return string.sub(joined, 5)
		end
		return joined
	end

	local isXh = string.find(source, "XHider", 1, true)
		or string.find(source, "ynvq7ED4Sp", 1, true)
		or string.find(source, "XHD:", 1, true)
	if isXh then
		emit("bytecode.const", "xhider")
		local body = xhExtractPayload(source)
		if type(body) == "string" and #body >= 20 then
			local raw = xhAscii85(body)
			if raw then
				local keysets = xhExtractKeysets(source)
				local bestList, bestScore = {}, -1
				local bestKeys = nil
				for _, keys in ipairs(keysets) do
					local list = xhWalk(raw, keys)
					local sc = xhScore(list)
					if sc > bestScore then
						bestScore, bestList, bestKeys = sc, list, keys
					end
				end
				local seen = {}
				for _, s in ipairs(bestList) do
					if not seen[s] then
						seen[s] = true
						emit("xhider.decoded", s)
						pcall(harvestCode, s, "xh")
					end
				end
			end
		end
		pcall(harvestCode, source, "xhstatic")
	end
end





-- WRD_X_DECODER: generic WeAreDevs (all builds)
-- Format A: M={"\\ddd..."} + N alphabet → custom base64
-- Format B: P={">...","L..."} + h/g alphabets → radix85 / base64 with prefix
do
	local function foldExpr(expr)
		if type(expr) ~= "string" then return nil end
		expr = string.gsub(expr, "%s+", "")
		local prev
		repeat
			prev = expr
			expr = string.gsub(expr, "%-%(%-(%d+)%)", "+%1")
		until expr == prev
		-- tokenize numbers and + - * %
		do
			local okc = true
			for ci = 1, #expr do
				local ch = string.sub(expr, ci, ci)
				if not string.match(ch, "%d") and ch ~= "+" and ch ~= "-" and ch ~= "*" and ch ~= "%" then
					okc = false
					break
				end
			end
			if not okc then return nil end
		end
		-- shunting: left-to-right for +-, *% have precedence via two-pass
		-- Pass1: handle * and %
		local tokens = {}
		local i = 1
		local sign = 1
		if string.sub(expr, 1, 1) == "-" then sign = -1; i = 2
		elseif string.sub(expr, 1, 1) == "+" then i = 2 end
		while i <= #expr do
			local j = i
			while j <= #expr and string.match(string.sub(expr, j, j), "%d") do j += 1 end
			if j == i then return nil end
			local n = tonumber(string.sub(expr, i, j - 1))
			if not n then return nil end
			n = sign * n
			-- look at following * or %
			while j <= #expr do
				local op = string.sub(expr, j, j)
				if op == "*" or op == "%" then
					j += 1
					local k = j
					local s2 = 1
					if string.sub(expr, j, j) == "-" then s2 = -1; j += 1; k = j
					elseif string.sub(expr, j, j) == "+" then j += 1; k = j end
					while k <= #expr and string.match(string.sub(expr, k, k), "%d") do k += 1 end
					if k == j then return nil end
					local m = tonumber(string.sub(expr, j, k - 1))
					if not m then return nil end
					m = s2 * m
					if op == "*" then n = n * m else n = n % m end
					j = k
				else
					break
				end
			end
			tokens[#tokens + 1] = n
			if j > #expr then break end
			local op = string.sub(expr, j, j)
			if op == "+" then sign = 1
			elseif op == "-" then sign = -1
			else return nil end
			i = j + 1
		end
		local total = 0
		for _, v in ipairs(tokens) do total += v end
		return total
	end

	local function parseMapBody(body)
		local map = {}
		for k, expr in string.gmatch(body, "([A-Za-z_])%s*=%s*([^,;]+)") do
			local v = foldExpr(expr)
			if v then map[k] = v end
		end
		for k, expr in string.gmatch(body, '%[%s*"((?:\\.|[^"\\])*)"%s*%]%s*=%s*([^,;]+)') do
			local key = string.gsub(k, "\\(.)", "%1")
			if #key == 1 then
				local v = foldExpr(expr)
				if v then map[key] = v end
			end
		end
		return map
	end

	local function extractMaps(src)
		local maps = {}
		local pos = 1
		while true do
			local s1 = string.find(src, "local%s+%w+%s*=%s*{", pos)
			if not s1 then break end
			local brace = string.find(src, "{", s1, true)
			if not brace then break end
			local depth, j = 1, brace + 1
			while j <= #src and depth > 0 do
				local ch = string.sub(src, j, j)
				if ch == "{" then depth += 1
				elseif ch == "}" then depth -= 1
				elseif ch == '"' or ch == "'" then
					local q = ch
					j += 1
					while j <= #src do
						local c2 = string.sub(src, j, j)
						if c2 == "\\" then j += 2
						elseif c2 == q then break
						else j += 1 end
					end
				end
				j += 1
			end
			local body = string.sub(src, brace + 1, j - 2)
			local map = parseMapBody(body)
			local n = 0
			for _ in pairs(map) do n += 1 end
			if n >= 40 then
				maps[#maps + 1] = map
			end
			pos = j
			if pos > #src then break end
		end
		return maps
	end

	local function extractStringPool(src)
		-- first large {"...","..."} after wearedevs / return(function
		local best, bestN = {}, 0
		local pos = 1
		while true do
			local s1 = string.find(src, "local%s+%w+%s*=%s*{", pos)
			if not s1 then break end
			local brace = string.find(src, "{", s1, true)
			if not brace then break end
			local parts = {}
			local p = brace + 1
			local limit = math.min(#src, brace + 250000)
			local depth = 1
			while p <= limit and depth > 0 do
				local ch = string.sub(src, p, p)
				if ch == "{" then depth += 1; p += 1
				elseif ch == "}" then depth -= 1; p += 1
				elseif ch == '"' then
					p += 1
					local buf = {}
					while p <= limit do
						local c = string.sub(src, p, p)
						if c == "\\" and p < limit then
							local n = string.sub(src, p + 1, p + 1)
							if string.match(n, "%d") then
								local j = p + 1
								while j <= limit and j < p + 4 and string.match(string.sub(src, j, j), "%d") do
									j += 1
								end
								local num = tonumber(string.sub(src, p + 1, j - 1))
								if num and num <= 255 then buf[#buf + 1] = string.char(num) end
								p = j
							elseif n == "n" then buf[#buf+1] = "\n"; p += 2
							elseif n == "t" then buf[#buf+1] = "\t"; p += 2
							elseif n == "r" then buf[#buf+1] = "\r"; p += 2
							elseif n == "\\" or n == '"' or n == "'" then buf[#buf+1] = n; p += 2
							else buf[#buf+1] = n; p += 2 end
						elseif c == '"' then
							p += 1
							break
						else
							buf[#buf + 1] = c
							p += 1
						end
					end
					parts[#parts + 1] = table.concat(buf)
				else
					p += 1
				end
			end
			if #parts > bestN then
				bestN, best = #parts, parts
			end
			pos = p
			if pos > #src then break end
		end
		return best
	end

	local function customB64(W, alphabet)
		if type(W) ~= "string" or #W < 1 then return nil end
		local q, h, S, i, b = {}, 0, 0, 1, #W
		while i <= b do
			local ch = string.sub(W, i, i)
			local x = alphabet[ch]
			if x then
				h = h + x * (64 ^ (3 - S))
				S = S + 1
				if S == 4 then
					S = 0
					q[#q + 1] = string.char(
						math.floor(h / 65536) % 256,
						math.floor((h % 65536) / 256) % 256,
						h % 256
					)
					h = 0
				end
			elseif ch == "=" then
				q[#q + 1] = string.char(math.floor(h / 65536) % 256)
				if i >= b or string.sub(W, i + 1, i + 1) ~= "=" then
					q[#q + 1] = string.char(math.floor((h % 65536) / 256) % 256)
				end
				break
			end
			i += 1
		end
		return table.concat(q)
	end

	local function radix85(body, alphabet)
		if type(body) ~= "string" or #body < 2 then return nil end
		local RADIX, PAD = 85, 84
		local out = {}
		local w, Wlen = 1, #body
		while w <= Wlen do
			local remain = Wlen - w + 1
			local d = remain >= 5 and 5 or remain
			if d < 2 then break end
			local E, ok = 0, true
			for P = 0, 4 do
				local W
				if P < d then
					W = alphabet[string.sub(body, w + P, w + P)]
					if not W then ok = false break end
				else
					W = PAD
				end
				E = E * RADIX + W
			end
			if ok then
				local b0 = math.floor(E / 16777216) % 256
				local b1 = math.floor(E / 65536) % 256
				local b2 = math.floor(E / 256) % 256
				local b3 = E % 256
				if d == 5 then out[#out+1] = string.char(b0, b1, b2, b3)
				elseif d == 4 then out[#out+1] = string.char(b0, b1, b2)
				elseif d == 3 then out[#out+1] = string.char(b0, b1)
				elseif d == 2 then out[#out+1] = string.char(b0)
				end
				w += d
			else
				w += 1
			end
		end
		return table.concat(out)
	end

	local function isClean(s)
		if type(s) ~= "string" or #s < 2 or #s > 8000 then return false end
		local g = 0
		for i = 1, #s do
			local b = string.byte(s, i)
			if (b >= 32 and b <= 126) or b == 9 or b == 10 then g += 1 end
		end
		return g / #s >= 0.85
	end

	local isWrd = string.find(source, "wearedevs", 1, true)
		or string.find(source, "wearedevs.net/obfuscator", 1, true)
	if isWrd then
		local maps = extractMaps(source)
		local pool = extractStringPool(source)
		local b64map, r85map = nil, nil
		for _, m in ipairs(maps) do
			local n, mx = 0, 0
			for _, v in pairs(m) do
				n += 1
				if v > mx then mx = v end
			end
			if n >= 60 and mx <= 63 and not b64map then b64map = m end
			if n >= 60 and mx >= 70 and mx <= 90 and not r85map then r85map = m end
		end
		-- also try every map on every string and keep best clean
		local seen = {}
		local function emitClean(s)
			if isClean(s) and not seen[s] then
				seen[s] = true
				emit("wrd.x", s)
				pcall(harvestCode, s, "wrdx")
			end
		end
		for _, W in ipairs(pool) do
			if type(W) == "string" and #W >= 1 then
				local pref = string.sub(W, 1, 1)
				local body = string.sub(W, 2)
				-- prefix L / none → base64 alphabets
				if b64map then
					if pref == "L" or pref == "T" or pref == "m" then
						emitClean(customB64(body, b64map))
					end
					emitClean(customB64(W, b64map))
				end
				-- prefix > / T → radix85
				if r85map then
					if pref == ">" or pref == "T" or pref == "m" then
	
					emitClean(radix85(body, r85map))
					end
					emitClean(radix85(W, r85map))
				end
				-- try all maps
				for _, m in ipairs(maps) do
					emitClean(customB64(W, m))
					if #W >= 2 then emitClean(radix85(string.sub(W, 2), m)) end
				end
			end
		end
	end
end



-- GENERIC VM register rewrite: any multi-stage return(function)...return(function) obfuscator
-- {} in the VM body → __reg() (numeric miss = 0). Applies to WRD, and similar packed VMs.
do
	local idxs = {}
	local pos = 1
	while true do
		local a, b = string.find(source, "return%s*%(%s*function", pos)
		if not a then break end
		idxs[#idxs + 1] = a
		pos = b + 1
		if #idxs >= 6 then break end
	end
	-- Also treat "return function" without paren
	if #idxs < 2 then
		pos = 1
		while true do
			local a, b = string.find(source, "return%s+function%s*%(", pos)
			if not a then break end
			idxs[#idxs + 1] = a
			pos = b + 1
			if #idxs >= 6 then break end
		end
	end
	local heavyVm = #idxs >= 2
		or string.find(source, "wearedevs", 1, true)
		or string.find(source, "Luraph", 1, true)
		or string.find(source, "IronBrew", 1, true)
		or string.find(source, "Moonsec", 1, true)
		or string.find(source, "Prometheus", 1, true)
	if heavyVm then
		-- rewrite entire source for max register safety (pool tables still work as arrays)
		local cut = 1
		local head = ""
		local vm = source
		if #idxs >= 2 then
			cut = idxs[math.min(2, #idxs)]
			head = string.sub(source, 1, cut - 1)
			vm = string.sub(source, cut)
		end
		local out = {}
		local i = 1
		while i <= #vm do
			local ch = string.sub(vm, i, i)
			if ch == '"' or ch == "'" then
				local q = ch
				out[#out + 1] = q
				i += 1
				while i <= #vm do
					local c = string.sub(vm, i, i)
					out[#out + 1] = c
					if c == "\\" and i < #vm then
						out[#out + 1] = string.sub(vm, i + 1, i + 1)
						i += 2
					elseif c == q then
						i += 1
						break
					else
						i += 1
					end
				end
			elseif string.sub(vm, i, i + 1) == "{}" then
				out[#out + 1] = "__reg()"
				i += 2
			else
				out[#out + 1] = ch
				i += 1
			end
		end
		source = head .. table.concat(out)
		-- Safe numeric coercion helper available as global
		source = "local function __n(v) local t=type(v) if t=='number' then return v end if t=='string' then return tonumber(v)or 0 end return 0 end\n" .. source
		-- WRD-style refcount: W[X]=W[X]-(CONST)  →  W[X]=__n(W[X])-(CONST)
		source = string.gsub(source, "([%w_]+)%[([%w_]+)%]%s*=%s*%1%[%2%]%s*%-%s*", "%1[%2]=__n(%1[%2])-")
		source = string.gsub(source, "([%w_]+)%[([%w_]+)%]%s*=%s*%1%[%2%]%s*%+%s*", "%1[%2]=__n(%1[%2])+")
		-- A=A+1 style for single-letter numeric counters used by WRD
		source = string.gsub(source, "([^%w_])([A-Za-z])(%s*=%s*)%2(%s*%+%s*)", function(a,v,eq,op)
			return a .. v .. eq .. "__n(" .. v .. ")" .. op
		end)
		source = string.gsub(source, "([^%w_])([A-Za-z])(%s*=%s*)%2(%s*%-%s*)", function(a,v,eq,op)
			return a .. v .. eq .. "__n(" .. v .. ")" .. op
		end)
	end
end

-- Prefer environment table (Lune); fallback preamble for older Lune
local loadOk, chunk
do
	local ok1, c1 = pcall(luau.load, source, { debugName = "chunk", environment = env })
	if ok1 and type(c1) == "function" then
		loadOk, chunk = true, c1
	else
		local preamble = "local " .. table.concat(envKeys, ",") .. " = ...\n"
		loadOk, chunk = pcall(luau.load, preamble .. source, { debugName = "chunk" })
		if loadOk and type(chunk) == "function" then
			local inner = chunk
			chunk = function()
				return inner(table.unpack(envVals, 1, #envVals))
			end
		end
	end
end
if not loadOk then
	lines[#lines + 1] = "[ERROR] load failed"
else
	-- Always run; Luraph hits budget via buffer/bit32/task.wait hooks (Lune has no debug.sethook)
	local isLuraphSrc = string.find(source, "Luraph", 1, true) or string.find(source, "lura.ph", 1, true)
	local isWeAreDevs = string.find(source, "wearedevs%.net/obfuscator", 1, true)
		or string.find(source, "wearedevs", 1, true)
		or string.find(source, 'local c={"T', 1, true)
	if isLuraphSrc then
		BUDGET = math.max(BUDGET, 45)
	end
	-- WeAreDevs: static T/m decode only — VM hits pow(string, number) in their interpreter
	local runOk, runErr = true, nil
	local isXHider = string.find(source, "XHider", 1, true)
		or string.find(source, "ynvq7ED4Sp", 1, true)
		or string.find(source, "XHD:", 1, true)
	local isHeavyVm = isWeAreDevs or isLuraphSrc or isXHider
		or string.find(source, "IronBrew", 1, true)
		or string.find(source, "Moonsec", 1, true)
		or string.find(source, "Prometheus", 1, true)
		or select(2, string.gsub(source, "return%s*%(%s*function", "")) >= 2
	if isHeavyVm then
		BUDGET = math.max(BUDGET, 90)
		dumpDead = false
		started = os.clock()
	end
	-- XHider / heavy VM: always run so hooks fire
	if isXHider then
		runOk = true
	end
	if true then
		if isWeAreDevs then
			BUDGET = 120
			dumpDead = false
			started = os.clock()
			-- Official pool decode only (second return(function is the VM)
			do
				local idxs = {}
				local pos = 1
				while true do
					local a, b = string.find(source, "return%s*%(%s*function", pos)
					if not a then break end
					idxs[#idxs + 1] = a
					pos = b + 1
				end
				if #idxs >= 2 then
					local head = string.sub(source, 1, idxs[2] - 1)
					local poolName = string.match(head, "local%s+([%w_]+)%s*=%s*{")
					if poolName then
						local tail = string.format([[
for __i = 1, #%s do
	local __v = %s[__i]
	if type(__v) == "string" and #__v >= 1 then
		emit("wrd.pool", __v)
	end
end
return function() end
end)(...)
]], poolName, poolName)
						local okp, fnp = pcall(luau.load, head .. tail, { debugName = "wrdpool", environment = env })
						if okp and type(fnp) == "function" then
							pcall(fnp)
							flushChar()
							flushUtf8()
						end
					end
				end
			end
		end
		-- WRD VMs often die on number+nil; retry with forced numeric metatable fallback via soft calls
		runOk, runErr = pcall(chunk)
		if not runOk and type(runErr) == "string" and string.find(runErr, "arithmetic", 1, true) then
			-- second chance: already emitted pool strings; soft-note only
			runOk = true
			lines[#lines + 1] = "[NOTE] partial VM (arith)"
		end
		flushChar()
		flushUtf8()
		if not runOk and type(runErr) == "string" then
			if not string.find(runErr, "budget", 1, true) then
				lines[#lines + 1] = "[NOTE] runtime stopped: " .. string.sub(tostring(runErr), 1, 120)
			else
				lines[#lines + 1] = "[NOTE] budget"
			end
		end
	end
	-- Phase 2: deep re-harvest every loadstring-src already captured + try small nested runs
	do
		local collected = {}
		for i = 1, #lines do
			local L = lines[i]
			if type(L) == "string" then
				local src = string.match(L, '%(loadstring%-src%)%s+"(.*)"%s*$')
				if not src then
					-- multi-line / long: extract after tag
					src = string.match(L, "loadstring%-src%)%s+(.+)$")
				end
				if type(src) == "string" and #src >= 20 and #src < 200000 then
					collected[#collected + 1] = src
					pcall(harvestCode, src, "p2")
				end
			end
		end
		-- also re-scan original source for embedded long strings again
		pcall(harvestCode, source, "p2static")
		-- try execute tiny nested payloads only
		local t0 = os.clock()
		for i = 1, math.min(#collected, 12) do
			if os.clock() - t0 > 8 then break end
			local code = collected[i]
			if #code < 8000 and not string.find(code, "while true", 1, true) then
				local okf, fn = pcall(luau.load, code, { debugName = "c2", environment = env })
				if okf and type(fn) == "function" then
					pcall(fn)
					flushChar()
					flushUtf8()
				end
			end
		end
	end
end

pcall(flushWord)
pcall(flushChar)
pcall(flushUtf8)
local out = table.concat(lines, "\n")
if #out == 0 then out = "[NOTE] no constants captured" end
out ..= string.format("\n\n-- %d strings\n", emitIndex)
if outputPath then fs.writeFile(outputPath, out) end
print(out)
