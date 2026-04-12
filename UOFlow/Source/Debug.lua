----------------------------------------------------------------
-- Debugging Assistance Variables
----------------------------------------------------------------

Debug = {}
Debug.Stringable = { ["nil"]=1, ["string"]=1, ["number"]=1, ["bool"]=1 }

function Debug.PrintToChat( text )
	TextLogAddEntry( "Chat", 100, text )
end

function Debug.PrintToDebugConsole( text )
	--if type(text) == "string" then
	--	text = StringToWString(text)
	--end
	
	TextLogAddEntry( "UiLog", 1, StringToWString(tostring(text)) )
	TextLogAddEntry("DebugPrint", 1, StringToWString(tostring(text)))
end

-- Shorter alias to PrintToDebugConsole
function Debug.Print(text)
	if (type(text) == "table") then
		Debug.DumpToConsole("", text)
	else
		Debug.PrintToDebugConsole(text)
	end
end

function Debug.DumpToConsole(name, value, memo)
	memo = memo or {}
	local t = type(value)
	local prefix = name.."="
	if Debug.Stringable[t] then
		Debug.Print(prefix..tostring(value))
	elseif t == "wstring" then
		Debug.Print(StringToWString(prefix)..value)
	elseif t == "boolean" then
		Debug.Print(StringToWString(prefix)..StringToWString(tostring(value)))
	elseif t == "table" then
		if memo[value] then
			Debug.Print(prefix..tostring(memo[value]))
		else
			memo[value] = name
			for k, v in pairs(value) do
				local fname = string.format("%s[%s]", name, tostring(k))
				Debug.DumpToConsole(fname, v, memo)
			end
		end
	else
		Debug.PrintToDebugConsole(StringToWString("Can't serialize type "..t))
	end
end

function Debug.Dump(name, value, memo)
	Debug.DumpToConsole(name, value, memo)
end

local function UOWLookupRawFunction(container, key)
	if type(container) ~= "table" or type(key) ~= "string" or key == "" then
		return nil
	end

	local value = rawget(container, key)
	if type(value) == "function" then
		return value
	end

	return nil
end

local function UOWIsProbablyCFunction(fn)
	if type(fn) ~= "function" then
		return false
	end
	if type(debug) == "table" and type(debug.getinfo) == "function" then
		local info = debug.getinfo(fn)
		if type(info) == "table" then
			return info.what == "C"
		end
	end
	return false
end

local function UOWResolveNativeLogger()
	local env = nil
	if type(getfenv) == "function" then
		local value = getfenv(1)
		if type(value) == "table" then
			env = value
		end
	end

	local globalTable = _G
	if not globalTable and env and type(env._G) == "table" then
		globalTable = env._G
	end

	local envUOW = type(env) == "table" and rawget(env, "UOW") or nil
	local globalUOW = type(globalTable) == "table" and rawget(globalTable, "UOW") or nil

	local candidates = {
		UOWLookupRawFunction(env, "uow_debug_log"),
		UOWLookupRawFunction(globalTable, "uow_debug_log"),
		type(envUOW) == "table" and type(envUOW.Debug) == "table" and UOWLookupRawFunction(envUOW.Debug, "Log") or nil,
		type(globalUOW) == "table" and type(globalUOW.Debug) == "table" and UOWLookupRawFunction(globalUOW.Debug, "Log") or nil,
		type(uow_debug_log) == "function" and uow_debug_log or nil,
		UOW and UOW.Debug and type(UOW.Debug.Log) == "function" and UOW.Debug.Log or nil,
	}

	for _, candidate in ipairs(candidates) do
		if UOWIsProbablyCFunction(candidate) then
			return candidate
		end
	end

	for _, candidate in ipairs(candidates) do
		if type(candidate) == "function" then
			return candidate
		end
	end

	return nil
end

function UOWNativeLog(...)
	local logFn = UOWResolveNativeLogger()
	if not logFn then
		return
	end

	local parts = {}
	for i = 1, select('#', ...) do
		parts[i] = tostring(select(i, ...))
	end

	local message = table.concat(parts, " ")
	if UOWIsProbablyCFunction(logFn) then
		logFn(message)
		return
	end

	pcall(logFn, message)
end


local function uow_log(...)
	UOWNativeLog(...)
	local fn = nil
	if type(d) == 'function' then
		fn = d
	elseif Debug and type(Debug.Print) == 'function' then
		fn = Debug.Print
	end
	if not fn then
		return
	end
	fn(...)
end

function uow_selftest_cast_twice(spellId, waitMs)
	uow_log('== cast twice test ==', spellId, waitMs)
	if type(spellId) ~= 'number' then
		uow_log('spellId must be numeric')
		return false, false
	end

	local castFn = UserActionCastSpell
	local castLabel = 'UserActionCastSpell'
	if type(uow_spell_cast) == 'function' then
		castFn = uow_spell_cast
		castLabel = 'uow_spell_cast'
	elseif UOFlow and UOFlow.Spell and type(UOFlow.Spell.cast) == 'function' then
		castFn = UOFlow.Spell.cast
		castLabel = 'UOFlow.Spell.cast'
	end

	uow_log('cast helper', castLabel)
	local ok1, res1 = pcall(castFn, spellId)
	uow_log('cast1', ok1, res1)

	local delayMs = tonumber(waitMs) or 0
	if delayMs > 0 then
		if WindowUtils and type(WindowUtils.SendOverheadText) == 'function' then
			local msg = towstring(string.format('wait %d ms', delayMs))
			pcall(WindowUtils.SendOverheadText, msg, 66, true, false)
		end
		if type(Delay) == 'function' then
			pcall(Delay, delayMs)
		else
			uow_log('Delay helper unavailable; skipping sleep', delayMs)
		end
	end

	if type(ClearCurrentTarget) == 'function' then
		local okClear, resClear = pcall(ClearCurrentTarget)
		uow_log('ClearCurrentTarget', okClear, resClear)
	end

	local ok2, res2 = pcall(castFn, spellId)
	uow_log('cast2', ok2, res2)
	return ok1 and res1, ok2 and res2
end
