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

local function UOWResolveDummyPrint()
	if type(DummyPrint) == "function" then
		return DummyPrint
	end

	local globalTable = _G
	if type(globalTable) == "table" then
		local rawDummy = rawget(globalTable, "DummyPrint")
		if type(rawDummy) == "function" then
			return rawDummy
		end
	end

	return nil
end

function UOWNativeLog(...)
	local logFn = UOWResolveDummyPrint()
	if type(logFn) ~= "function" then
		return
	end

	local parts = {}
	for i = 1, select('#', ...) do
		parts[i] = tostring(select(i, ...))
	end

	local message = table.concat(parts, " ")
	logFn(message)
end

local function UOWResolveRawSpellCast()
	if type(UOWCastSpellRaw) == "function" then
		return UOWCastSpellRaw
	end

	local globalTable = _G
	if type(globalTable) == "table" then
		local rawFn = rawget(globalTable, "UOWCastSpellRaw")
		if type(rawFn) == "function" then
			return rawFn
		end
	end

	return nil
end

local function UOWResolveRawSpellCastOnId()
	if type(UOWCastSpellOnIdRaw) == "function" then
		return UOWCastSpellOnIdRaw
	end

	local globalTable = _G
	if type(globalTable) == "table" then
		local rawFn = rawget(globalTable, "UOWCastSpellOnIdRaw")
		if type(rawFn) == "function" then
			return rawFn
		end
	end

	return nil
end

local function UOWSpellCastWrapper(spellId)
	local numericSpellId = tonumber(spellId)
	if not numericSpellId or numericSpellId <= 0 then
		UOWNativeLog("[LuaSpell] cast invalid spellId=", tostring(spellId))
		return false, "native_cast_failed"
	end

	local rawCast = UOWResolveRawSpellCast()
	if type(rawCast) ~= "function" then
		UOWNativeLog("[LuaSpell] cast raw missing spellId=", tostring(numericSpellId))
		return false, "native_cast_failed"
	end

	UOWNativeLog("[LuaSpell] cast request spellId=", tostring(numericSpellId))
	local ok = rawCast(numericSpellId)
	local success = (ok == true)
	UOWNativeLog(
		"[LuaSpell] cast result spellId=",
		tostring(numericSpellId),
		" ok=",
		tostring(success),
		" raw=",
		tostring(ok))

	if success then
		return true, "ok"
	end

	return false, "native_cast_failed"
end

local function UOWSpellCastOnIdWrapper(spellId, objectId)
	local numericSpellId = tonumber(spellId)
	local numericObjectId = tonumber(objectId)
	if not numericSpellId or numericSpellId <= 0 or not numericObjectId or numericObjectId <= 0 then
		UOWNativeLog("[LuaSpell] cast_on_id invalid args spellId=", tostring(spellId), " target=", tostring(objectId))
		return false, "native_cast_failed"
	end

	local rawCast = UOWResolveRawSpellCastOnId()
	if type(rawCast) ~= "function" then
		UOWNativeLog("[LuaSpell] cast_on_id raw missing spellId=", tostring(numericSpellId), " target=", tostring(numericObjectId))
		return false, "native_cast_failed"
	end

	UOWNativeLog("[LuaSpell] cast_on_id request spellId=", tostring(numericSpellId), " target=", tostring(numericObjectId))
	local ok = rawCast(numericSpellId, numericObjectId)
	local success = (ok ~= false)
	UOWNativeLog(
		"[LuaSpell] cast_on_id result spellId=",
		tostring(numericSpellId),
		" target=",
		tostring(numericObjectId),
		" ok=",
		tostring(success),
		" raw=",
		tostring(ok))

	if success then
		return true, "ok"
	end

	return false, "native_cast_failed"
end

function UOWInstallLuaSpellWrappers()
	local globalTable = _G
	if type(globalTable) ~= "table" then
		return false
	end

	globalTable.UOFlow = type(globalTable.UOFlow) == "table" and globalTable.UOFlow or {}
	globalTable.UOFlow.Spell = type(globalTable.UOFlow.Spell) == "table" and globalTable.UOFlow.Spell or {}
	globalTable.UOW = type(globalTable.UOW) == "table" and globalTable.UOW or {}
	globalTable.UOW.Spell = type(globalTable.UOW.Spell) == "table" and globalTable.UOW.Spell or {}
	globalTable.uow = type(globalTable.uow) == "table" and globalTable.uow or {}
	globalTable.uow.cmd = type(globalTable.uow.cmd) == "table" and globalTable.uow.cmd or {}

	globalTable.UOFlow.Spell.cast = UOWSpellCastWrapper
	globalTable.UOFlow.Spell.cast_on_id = UOWSpellCastOnIdWrapper
	globalTable.UOW.Spell.cast = UOWSpellCastWrapper
	globalTable.UOW.Spell.cast_on_id = UOWSpellCastOnIdWrapper
	globalTable.uow.cmd.cast = UOWSpellCastWrapper
	globalTable.uow.cmd.cast_on_id = UOWSpellCastOnIdWrapper
	return true
end

UOWInstallLuaSpellWrappers()


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

	if type(UOWInstallLuaSpellWrappers) == "function" then
		UOWInstallLuaSpellWrappers()
	end

	local castFn = UOFlow and UOFlow.Spell and UOFlow.Spell.cast
	local castLabel = 'UOFlow.Spell.cast'
	if type(castFn) ~= 'function' then
		uow_log('cast helper missing', castLabel)
		return false, false
	end

	uow_log('cast helper', castLabel)
	local ok1, res1 = true, castFn(spellId)
	uow_log('cast1', ok1, res1)

	local delayMs = tonumber(waitMs) or 0
	if delayMs > 0 then
		if WindowUtils and type(WindowUtils.SendOverheadText) == 'function' then
			local msg = towstring(string.format('wait %d ms', delayMs))
			WindowUtils.SendOverheadText(msg, 66, true, false)
		end
		if type(Delay) == 'function' then
			Delay(delayMs)
		else
			uow_log('Delay helper unavailable; skipping sleep', delayMs)
		end
	end

	if type(ClearCurrentTarget) == 'function' then
		local okClear, resClear = true, ClearCurrentTarget()
		uow_log('ClearCurrentTarget', okClear, resClear)
	end

	local ok2, res2 = true, castFn(spellId)
	uow_log('cast2', ok2, res2)
	return ok1 and res1, ok2 and res2
end
