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


local function uow_log(...)
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

	local ok1, res1 = pcall(UserActionCastSpell, spellId)
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

	local ok2, res2 = pcall(UserActionCastSpell, spellId)
	uow_log('cast2', ok2, res2)
	return ok1 and res1, ok2 and res2
end
