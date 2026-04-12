-- Block type definitions and utilities

-- Timer system with function queue
VisualProgrammingInterface.ActionTimer = Timer:new()

-- Register a completion callback
function VisualProgrammingInterface.ActionTimer:registerCompletionCallback(callbackName, callback)
    self.completionCallbacks[callbackName] = callback
end

-- Notify all registered completion callbacks
function VisualProgrammingInterface.ActionTimer:notifyCompletion()
    for _, callback in pairs(self.completionCallbacks) do
        if type(callback) == "function" then
            callback()
        end
    end
end

-- Clean up timer state
function VisualProgrammingInterface.ActionTimer:reset()
    Timer.reset(self)
end

function VisualProgrammingInterface.ActionTimer:OnUpdate(timePassed)
    -- Ensure this method does not call itself recursively
    Timer.OnUpdate(self, timePassed)
end

-- Helper function for waiting
local function WaitTimer(duration, callback, queueId)
    Debug.Print("WaitTimer called: " .. duration .. "ms, queue: " .. tostring(queueId))
    VisualProgrammingInterface.ActionTimer:start(duration, callback, queueId)
    return true
end

local function VPValueToString(value)
    if value == nil then
        return "<nil>"
    end
    return tostring(value)
end

local function VPGetLuaContextTag()
    local env = nil
    if type(getfenv) == "function" then
        env = getfenv(1)
    end

    if type(env) == "table" then
        local tagged = rawget(env, "__uow_context_tag")
        if tagged ~= nil then
            return tostring(tagged)
        end
        return tostring(env)
    end

    if type(_G) == "table" then
        local tagged = rawget(_G, "__uow_context_tag")
        if tagged ~= nil then
            return tostring(tagged)
        end
    end

    return "<nil>"
end

local function ResolveNativeLog()
    if type(UOWNativeLog) == "function" then
        return UOWNativeLog
    end
    if type(uow_debug_log) == "function" then
        return uow_debug_log
    end
    if type(_G) == "table" then
        local rawGlobalLog = rawget(_G, "uow_debug_log")
        if type(rawGlobalLog) == "function" then
            return rawGlobalLog
        end
    end
    if type(uow) == "table" and type(uow.debug_log) == "function" then
        return uow.debug_log
    end
    return nil
end

local function VPNativeLog(...)
    local logFn = ResolveNativeLog()
    if type(logFn) == "function" then
        return logFn(...)
    end
    return nil
end

local function VPEmitUiLog(message)
    local text = VPValueToString(message)
    VPNativeLog(text)
    if type(Debug) == "table" and type(Debug.Print) == "function" then
        Debug.Print(text)
    end
end

if type(_G) == "table" and not rawget(_G, "__UOW_VP_MARKER_B914507") then
    rawset(_G, "__UOW_VP_MARKER_B914507", true)
    local marker = "[VP_MARKER] VisualProgrammingTypes.lua build=b914507 loaded"
    VPNativeLog(marker)
    if type(Debug) == "table" and type(Debug.Print) == "function" then
        Debug.Print(marker)
    end
end

local function VPBuildCallContext(params, fallbackTag)
    local blockId = params and params.__vpBlockId or nil
    local blockType = params and params.__vpBlockType or nil
    local executionTag = params and params.__vpExecutionTag or nil
    if not executionTag then
        executionTag = "VP:block=" .. tostring(blockId) .. ":type=" .. tostring(blockType or fallbackTag)
    end

    return {
        blockId = blockId,
        blockType = blockType,
        executionTag = executionTag,
        luaContextTag = VPGetLuaContextTag()
    }
end

local function VPBuildCastSourceTag(tag, callContext, helperLabel)
    local blockId = type(callContext) == "table" and callContext.blockId or nil
    local executionTag = type(callContext) == "table" and callContext.executionTag or tag
    return string.format(
        "VP|tag=%s|block=%s|helper=%s",
        VPValueToString(executionTag or tag),
        VPValueToString(blockId),
        VPValueToString(helperLabel))
end

local function VPShouldPassCastSourceTag(label)
    if type(label) ~= "string" then
        return false
    end

    return string.find(label, "UOFlow.Spell.cast", 1, true) ~= nil
        or string.find(label, "UOW.Spell.cast", 1, true) ~= nil
        or string.find(label, "uow.cmd.cast", 1, true) ~= nil
        or string.find(label, "uow_spell_cast", 1, true) ~= nil
end

local function VPShouldPassCastOnIdSourceTag(label)
    if type(label) ~= "string" then
        return false
    end

    return string.find(label, "UOFlow.Spell.cast_on_id", 1, true) ~= nil
        or string.find(label, "UOW.Spell.cast_on_id", 1, true) ~= nil
        or string.find(label, "uow_spell_cast_on_id", 1, true) ~= nil
end

local function VPLogCastCall(phase, tag, spellId, helperLabel, callContext, ok, result1, result2, errText)
    local uoflowType = type(UOFlow)
    local spellTableType = uoflowType == "table" and type(UOFlow.Spell) or "<nil>"
    local castType = (uoflowType == "table" and spellTableType == "table") and type(UOFlow.Spell.cast) or "<nil>"
    local executionTag = type(callContext) == "table" and callContext.executionTag or tag
    local luaContextTag = type(callContext) == "table" and callContext.luaContextTag or VPGetLuaContextTag()
    local blockId = type(callContext) == "table" and callContext.blockId or nil

    local message = string.format(
        "[VP_CAST] phase=%s block=%s spell=%s helper=%s type(UOFlow)=%s type(UOFlow.Spell)=%s type(UOFlow.Spell.cast)=%s ctx=%s luaCtx=%s ok=%s ret1=%s ret2=%s err=%s",
        VPValueToString(phase),
        VPValueToString(blockId),
        VPValueToString(spellId),
        VPValueToString(helperLabel),
        VPValueToString(uoflowType),
        VPValueToString(spellTableType),
        VPValueToString(castType),
        VPValueToString(executionTag),
        VPValueToString(luaContextTag),
        VPValueToString(ok),
        VPValueToString(result1),
        VPValueToString(result2),
        VPValueToString(errText))

    VPNativeLog(message)
    Debug.Print(message)
end

local function VPLogSpellState(tag, spellId)
    local activeWindow = "<nil>"
    if SystemData and SystemData.ActiveWindow then
        activeWindow = VPValueToString(SystemData.ActiveWindow.name)
    end

    local useSpell = "<nil>"
    local useTarget = "<nil>"
    if GameData and GameData.UseRequests then
        useSpell = VPValueToString(GameData.UseRequests.UseSpellcast)
        useTarget = VPValueToString(GameData.UseRequests.UseTarget)
    end

    local lastSpell = "<nil>"
    local currentSpellId = "<nil>"
    local currentSpellCasting = "<nil>"
    if Interface then
        lastSpell = VPValueToString(Interface.LastSpell)
        if Interface.CurrentSpell then
            currentSpellId = VPValueToString(Interface.CurrentSpell.SpellId)
            currentSpellCasting = VPValueToString(Interface.CurrentSpell.casting)
        end
    end

    Debug.Print(string.format(
        "[VPSpell] %s spell=%s activeWindow=%s useSpell=%s useTarget=%s lastSpell=%s currentSpellId=%s currentSpellCasting=%s",
        VPValueToString(tag),
        VPValueToString(spellId),
        activeWindow,
        useSpell,
        useTarget,
        lastSpell,
        currentSpellId,
        currentSpellCasting))
end

local function VPDescribeCandidate(label, value)
    local suffix = ""
    if type(value) == "function" and type(debug) == "table" and type(debug.getinfo) == "function" then
        local info = debug.getinfo(value)
        if type(info) == "table" then
            suffix = suffix .. string.format(" impl=%s", info.what == "C" and "c" or "lua")
            if info.what ~= "C" and type(string) == "table" and type(string.dump) == "function" then
                local dumped = string.dump(value)
                suffix = suffix .. string.format(" dump=%s", VPValueToString(string.len and string.len(dumped) or #dumped))
            end
            suffix = string.format(
                "%s what=%s src=%s line=%s nups=%s",
                suffix,
                VPValueToString(info.what),
                VPValueToString(info.short_src or info.source),
                VPValueToString(info.linedefined),
                VPValueToString(info.nups))
        end
    end
    return string.format("%s=%s/%s%s", label, type(value), VPValueToString(value), suffix)
end

local function VPLogFunctionIdentity(tag, helperLabel, fn, passSourceTag)
    local what = "<nil>"
    if type(fn) == "function" and type(debug) == "table" and type(debug.getinfo) == "function" then
        local info = debug.getinfo(fn)
        if type(info) == "table" then
            what = VPValueToString(info.what)
        end
    end

    local message = string.format(
        "[VPSpell] fn identity tag=%s helper=%s type=%s what=%s fn=%s passSourceTag=%s",
        VPValueToString(tag),
        VPValueToString(helperLabel),
        VPValueToString(type(fn)),
        VPValueToString(what),
        VPValueToString(fn),
        VPValueToString(passSourceTag))

    VPNativeLog(message)
    Debug.Print(message)
end

local function VPLookupRawFunction(container, key)
    if type(container) ~= "table" or type(key) ~= "string" or key == "" then
        return nil
    end

    local value = rawget(container, key)
    if type(value) == "function" then
        return value
    end

    return nil
end

local function VPLookupRawPath(container, ...)
    if type(container) ~= "table" then
        return nil
    end

    local current = container
    local partCount = select("#", ...)
    for i = 1, partCount do
        local key = select(i, ...)
        if type(current) ~= "table" or type(key) ~= "string" or key == "" then
            return nil
        end

        local value = rawget(current, key)
        current = value
    end

    if type(current) == "function" then
        return current
    end
    return nil
end

local function VPSnapshotSpellState()
    return {
        activeWindow = (SystemData and SystemData.ActiveWindow and VPValueToString(SystemData.ActiveWindow.name)) or "<nil>",
        useSpell = (GameData and GameData.UseRequests and VPValueToString(GameData.UseRequests.UseSpellcast)) or "<nil>",
        useTarget = (GameData and GameData.UseRequests and VPValueToString(GameData.UseRequests.UseTarget)) or "<nil>",
        lastSpell = (Interface and VPValueToString(Interface.LastSpell)) or "<nil>",
        currentSpellId = (Interface and Interface.CurrentSpell and VPValueToString(Interface.CurrentSpell.SpellId)) or "<nil>",
        currentSpellCasting = (Interface and Interface.CurrentSpell and VPValueToString(Interface.CurrentSpell.casting)) or "<nil>",
    }
end

local function VPDidSpellStateChange(beforeState)
    local afterState = VPSnapshotSpellState()
    if not beforeState then
        return false
    end
    return beforeState.activeWindow ~= afterState.activeWindow
        or beforeState.useSpell ~= afterState.useSpell
        or beforeState.useTarget ~= afterState.useTarget
        or beforeState.lastSpell ~= afterState.lastSpell
        or beforeState.currentSpellId ~= afterState.currentSpellId
        or beforeState.currentSpellCasting ~= afterState.currentSpellCasting
end

local function VPIsHardCastSuccess(result1, stateChanged)
    return result1 == true or stateChanged == true
end

local function VPResolveSpellHelpers()
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

    local normalUOFlowSpellCast = type(UOFlow) == "table" and type(UOFlow.Spell) == "table" and type(UOFlow.Spell.cast) == "function" and UOFlow.Spell.cast or nil
    local normalUOWSpellCast = type(UOW) == "table" and type(UOW.Spell) == "table" and type(UOW.Spell.cast) == "function" and UOW.Spell.cast or nil
    local normalCmdCast = type(uow) == "table" and type(uow.cmd) == "table" and type(uow.cmd.cast) == "function" and uow.cmd.cast or nil
    local normalUserActionCastSpell = type(UserActionCastSpell) == "function" and UserActionCastSpell or nil

    local rawEnvUOFlowSpellCast = VPLookupRawPath(env, "UOFlow", "Spell", "cast")
    local rawGlobalUOFlowSpellCast = VPLookupRawPath(globalTable, "UOFlow", "Spell", "cast")
    local rawEnvUOWSpellCast = VPLookupRawPath(env, "UOW", "Spell", "cast")
    local rawGlobalUOWSpellCast = VPLookupRawPath(globalTable, "UOW", "Spell", "cast")
    local rawEnvCmdCast = VPLookupRawPath(env, "uow", "cmd", "cast")
    local rawGlobalCmdCast = VPLookupRawPath(globalTable, "uow", "cmd", "cast")
    local rawEnvUserActionCastSpell = VPLookupRawFunction(env, "UserActionCastSpell")
    local rawGlobalUserActionCastSpell = VPLookupRawFunction(globalTable, "UserActionCastSpell")

    local candidates = {
        { label = "UOFlow.Spell.cast(raw env)", fn = rawEnvUOFlowSpellCast },
        { label = "UOFlow.Spell.cast(raw _G)", fn = rawGlobalUOFlowSpellCast },
        { label = "UOW.Spell.cast(raw env)", fn = rawEnvUOWSpellCast },
        { label = "UOW.Spell.cast(raw _G)", fn = rawGlobalUOWSpellCast },
        { label = "uow.cmd.cast(raw env)", fn = rawEnvCmdCast },
        { label = "uow.cmd.cast(raw _G)", fn = rawGlobalCmdCast },
        { label = "uow_spell_cast(env)", fn = env and VPLookupRawFunction(env, "uow_spell_cast") or nil },
        { label = "uow_spell_cast(_G)", fn = globalTable and VPLookupRawFunction(globalTable, "uow_spell_cast") or nil },
        { label = "UOFlow.Spell.cast", fn = normalUOFlowSpellCast },
        { label = "UOW.Spell.cast", fn = normalUOWSpellCast },
        { label = "uow.cmd.cast", fn = normalCmdCast },
        { label = "UserActionCastSpell(raw env)", fn = rawEnvUserActionCastSpell },
        { label = "UserActionCastSpell(raw _G)", fn = rawGlobalUserActionCastSpell },
    }

    local details = {
        VPDescribeCandidate("env", env),
        VPDescribeCandidate("_G", globalTable),
        VPDescribeCandidate("UserActionCastSpell", normalUserActionCastSpell),
        VPDescribeCandidate("UserActionCastSpell(raw env)", rawEnvUserActionCastSpell),
        VPDescribeCandidate("UserActionCastSpell(raw _G)", rawGlobalUserActionCastSpell),
        VPDescribeCandidate("uow_debug_log(env)", env and VPLookupRawFunction(env, "uow_debug_log") or nil),
        VPDescribeCandidate("uow_debug_log(_G)", globalTable and VPLookupRawFunction(globalTable, "uow_debug_log") or nil),
        VPDescribeCandidate("UOFlow.Spell.cast(raw env)", rawEnvUOFlowSpellCast),
        VPDescribeCandidate("UOFlow.Spell.cast(raw _G)", rawGlobalUOFlowSpellCast),
        VPDescribeCandidate("UOW.Spell.cast(raw env)", rawEnvUOWSpellCast),
        VPDescribeCandidate("UOW.Spell.cast(raw _G)", rawGlobalUOWSpellCast),
        VPDescribeCandidate("uow.cmd.cast(raw env)", rawEnvCmdCast),
        VPDescribeCandidate("uow.cmd.cast(raw _G)", rawGlobalCmdCast),
    }

    for _, candidate in ipairs(candidates) do
        table.insert(details, VPDescribeCandidate(candidate.label, candidate.fn))
    end

    return candidates, table.concat(details, " | ")
end

local function VPResolveCastSpellOnIdHelpers()
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

    local normalCastOnId = type(UserActionCastSpellOnId) == "function" and UserActionCastSpellOnId or nil
    local normalUOFlowCastOnId = type(UOFlow) == "table" and type(UOFlow.Spell) == "table"
        and type(UOFlow.Spell.cast_on_id) == "function" and UOFlow.Spell.cast_on_id or nil
    local normalUOWCastOnId = type(UOW) == "table" and type(UOW.Spell) == "table"
        and type(UOW.Spell.cast_on_id) == "function" and UOW.Spell.cast_on_id or nil
    local rawEnvCastOnId = VPLookupRawFunction(env, "UserActionCastSpellOnId")
    local rawGlobalCastOnId = VPLookupRawFunction(globalTable, "UserActionCastSpellOnId")
    local rawEnvUOFlowCastOnId = VPLookupRawPath(env, "UOFlow", "Spell", "cast_on_id")
    local rawGlobalUOFlowCastOnId = VPLookupRawPath(globalTable, "UOFlow", "Spell", "cast_on_id")
    local rawEnvUOWCastOnId = VPLookupRawPath(env, "UOW", "Spell", "cast_on_id")
    local rawGlobalUOWCastOnId = VPLookupRawPath(globalTable, "UOW", "Spell", "cast_on_id")

    local candidates = {
        { label = "UOFlow.Spell.cast_on_id(raw env)", fn = rawEnvUOFlowCastOnId },
        { label = "UOFlow.Spell.cast_on_id(raw _G)", fn = rawGlobalUOFlowCastOnId },
        { label = "UOW.Spell.cast_on_id(raw env)", fn = rawEnvUOWCastOnId },
        { label = "UOW.Spell.cast_on_id(raw _G)", fn = rawGlobalUOWCastOnId },
        { label = "UserActionCastSpellOnId(raw env)", fn = rawEnvCastOnId },
        { label = "UserActionCastSpellOnId(raw _G)", fn = rawGlobalCastOnId },
        { label = "UOFlow.Spell.cast_on_id", fn = normalUOFlowCastOnId },
        { label = "UOW.Spell.cast_on_id", fn = normalUOWCastOnId },
        { label = "UserActionCastSpellOnId", fn = normalCastOnId },
    }

    local details = {
        VPDescribeCandidate("UOFlow.Spell.cast_on_id", normalUOFlowCastOnId),
        VPDescribeCandidate("UOW.Spell.cast_on_id", normalUOWCastOnId),
        VPDescribeCandidate("UserActionCastSpellOnId", normalCastOnId),
        VPDescribeCandidate("UserActionCastSpellOnId(raw env)", rawEnvCastOnId),
        VPDescribeCandidate("UserActionCastSpellOnId(raw _G)", rawGlobalCastOnId),
        VPDescribeCandidate("UOFlow.Spell.cast_on_id(raw env)", rawEnvUOFlowCastOnId),
        VPDescribeCandidate("UOFlow.Spell.cast_on_id(raw _G)", rawGlobalUOFlowCastOnId),
        VPDescribeCandidate("UOW.Spell.cast_on_id(raw env)", rawEnvUOWCastOnId),
        VPDescribeCandidate("UOW.Spell.cast_on_id(raw _G)", rawGlobalUOWCastOnId),
    }

    return candidates, table.concat(details, " | ")
end

local function VPIsProbablyCFunction(fn)
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

local function VPInvokeFunction(fn, ...)
    if type(fn) ~= "function" then
        return false, nil, nil, "not_function"
    end

    local result1, result2 = fn(...)
    return true, result1, result2, nil
end

local function VPQueuePendingNativeSpellcast(spellId, tag, callContext)
    local pendingSource = type(callContext) == "table" and callContext.executionTag or tag
    local reason = "pending_not_supported"

    VPNativeLog("[VPSpell] pending disabled",
        tostring(tag),
        "spell=" .. tostring(spellId),
        "source=" .. tostring(pendingSource),
        "reason=" .. tostring(reason))
    Debug.Print(string.format(
        "[VPSpell] %s pending disabled spell=%s source=%s reason=%s",
        VPValueToString(tag),
        VPValueToString(spellId),
        VPValueToString(pendingSource),
        VPValueToString(reason)))

    return false, reason
end

local function VPCastSpell(spellId, tag, targetId, callContext)
    local numericSpellId = tonumber(spellId)
    if not numericSpellId or numericSpellId <= 0 then
        local invalidMsg = "VP_CAST invalid_spell_id spellId=" .. VPValueToString(spellId)
        VPEmitUiLog(invalidMsg)
        return false, invalidMsg, nil, false
    end

    spellId = numericSpellId
    callContext = type(callContext) == "table" and callContext or {}
    callContext.executionTag = callContext.executionTag or tag
    callContext.luaContextTag = callContext.luaContextTag or VPGetLuaContextTag()

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

    local castCandidates = {
        { label = "uow_spell_cast(raw _G)", fn = globalTable and VPLookupRawFunction(globalTable, "uow_spell_cast") or nil },
        { label = "uow_spell_cast(global)", fn = type(uow_spell_cast) == "function" and uow_spell_cast or nil },
        { label = "uow.cmd.cast(raw _G)", fn = VPLookupRawPath(globalTable, "uow", "cmd", "cast") },
    }
    local castLabel = nil
    local castFn = nil
    local candidateSummary = {
        VPDescribeCandidate("env", env),
        VPDescribeCandidate("_G", globalTable),
        VPDescribeCandidate("uow_spell_cast(raw _G)", castCandidates[1].fn),
        VPDescribeCandidate("uow_spell_cast(global)", castCandidates[2].fn),
        VPDescribeCandidate("uow.cmd.cast(raw _G)", castCandidates[3].fn),
    }

    VPNativeLog("[VPSpell] cast begin",
        tostring(tag),
        "spell=" .. tostring(spellId),
        "ctx=" .. tostring(callContext.executionTag),
        "targetId=" .. tostring(targetId))
    VPNativeLog("[VPSpell] cast candidates", tostring(tag), table.concat(candidateSummary, " | "))
    Debug.Print("[VPSpell] cast candidates " .. table.concat(candidateSummary, " | "))
    VPLogSpellState(tag .. ":before", spellId)

    for _, candidate in ipairs(castCandidates) do
        if type(candidate.fn) == "function" then
            castLabel = candidate.label
            castFn = candidate.fn
            break
        end
    end

    if type(castFn) ~= "function" then
        local missingMsg = "cast_helper_missing helper=uow_spell_cast/raw _G/global or uow.cmd.cast(raw _G)"
        VPEmitUiLog("VP_CAST " .. missingMsg)
        VPNativeLog("[VPSpell] cast fail", tostring(tag), missingMsg)
        VPLogSpellState(tag .. ":after", spellId)
        return false, missingMsg, nil, false
    end

    local helperSourceTag = VPBuildCastSourceTag(tag, callContext, castLabel)
    local beforeState = VPSnapshotSpellState()
    local ok = false
    local result1 = nil
    local result2 = nil
    local errText = nil

    VPLogCastCall("before", tag, spellId, castLabel, callContext, nil, nil, nil, nil)
    if type(_G) == "table" then
        rawset(_G, "uow_vp_cast_active", helperSourceTag)
    end

    local passSourceTag = VPShouldPassCastSourceTag(castLabel)
    VPLogFunctionIdentity(tag, castLabel, castFn, passSourceTag)
    if type(globalTable) == "table" then
        local nativeProbe = rawget(globalTable, "uow_debug_log")
        if type(nativeProbe) == "function" then
            nativeProbe("[VP_NATIVE_TEST] before cast helper=" .. tostring(castLabel))
        end
    end
    if passSourceTag then
        ok, result1, result2, errText = VPInvokeFunction(castFn, spellId, helperSourceTag)
    else
        ok, result1, result2, errText = VPInvokeFunction(castFn, spellId)
    end

    local stateChanged = VPDidSpellStateChange(beforeState)
    local hardSuccess = ok and VPIsHardCastSuccess(result1, stateChanged)
    VPLogCastCall("after", tag, spellId, castLabel, callContext, ok, result1, result2, errText)
    VPNativeLog("[VPSpell] helper result",
        tostring(tag),
        "helper=" .. tostring(castLabel),
        "ok=" .. tostring(ok),
        "result1=" .. tostring(result1),
        "result2=" .. tostring(result2),
        "stateChanged=" .. tostring(stateChanged),
        "hardSuccess=" .. tostring(hardSuccess),
        "source=" .. tostring(helperSourceTag))
    Debug.Print(string.format(
        "[VPSpell] %s helper=%s ok=%s result1=%s result2=%s stateChanged=%s hardSuccess=%s source=%s",
        VPValueToString(tag),
        VPValueToString(castLabel),
        VPValueToString(ok),
        VPValueToString(result1),
        VPValueToString(result2),
        VPValueToString(stateChanged),
        VPValueToString(hardSuccess),
        VPValueToString(helperSourceTag)))

    if hardSuccess then
        if stateChanged and result1 ~= true then
            result1 = true
            if result2 == nil then
                result2 = "state_changed"
            end
        end
        VPLogSpellState(tag .. ":after", spellId)
        return true, result1, result2, false
    end

    local hardFail = string.format(
        "hard_cast_fail helper=%s ok=%s ret1=%s ret2=%s stateChanged=%s err=%s",
        VPValueToString(castLabel),
        VPValueToString(ok),
        VPValueToString(result1),
        VPValueToString(result2),
        VPValueToString(stateChanged),
        VPValueToString(errText))
    VPEmitUiLog("VP_CAST " .. hardFail)
    VPLogSpellState(tag .. ":after", spellId)
    return false, hardFail, nil, false
end

-- Initialize block types
function VisualProgrammingInterface.InitializeBlockTypes()
    Debug.Print("Initializing block types")
    
    local Categories = VisualProgrammingInterface.Actions.categories
    
    -- General Actions
    VisualProgrammingInterface.Actions:register({
        name = "Say",
        description = L"Say something in chat",
        category = Categories.GENERAL,
        icon = { texture = "icon000632", x = 5, y = 5 },
        params = {
            CreateParameter("text", "string", "Hello")
        },
        execute = function(params)
            UserActionSay(StringToWString(params.text))
            return true
        end
    })

    -- Magic Actions
    VisualProgrammingInterface.Actions:register({
        name = "Cast Spell",
        description = L"Cast a selected spell",
        category = Categories.MAGIC,
        icon = { texture = "icon000640", x = 5, y = 5 },
        params = {
            CreateParameter("spellId", "select", "Clumsy", (function()
                -- Initialize SpellsInfo if needed
                if not SpellsInfo.SpellsData then
                    SpellsInfo.Initialize()
                end
                
                -- Collect all spell names
                local spellNames = {}
                for _, data in pairs(SpellsInfo.SpellsData) do
                    if type(data) == "table" and data.name then
                        table.insert(spellNames, data.name)
                    end
                end
                -- Sort alphabetically
                table.sort(spellNames)
                return spellNames
            end)()),
            CreateParameter("target", "select", "self", {"self", "target", "last"})
        },
        validate = function(params)
            -- Initialize SpellsInfo if needed
            if not SpellsInfo.SpellsData then
                SpellsInfo.Initialize()
            end
            -- Check if spell exists
            for _, data in pairs(SpellsInfo.SpellsData) do
                if type(data) == "table" and data.name == params.spellId then
                    return true
                end
            end
            return false
        end,
        execute = function(params)
            Debug.Print("Executing Cast Spell action")
            local callContext = VPBuildCallContext(params, "VisualProgramming.CastSpell")
            VPNativeLog("[VPSpell] execute", "block=" .. tostring(callContext.blockId), "requested=" .. tostring(params.spellId), "target=" .. tostring(params.target), "ctx=" .. tostring(callContext.executionTag))
            -- Look up spell ID from name
            local spellId = nil
            for word, data in pairs(SpellsInfo.SpellsData) do
                if data.name == params.spellId then
                    spellId = data.id
                    break
                end
            end
            
            if spellId then
                Debug.Print("Found spell ID: " .. spellId)
                VPNativeLog("[VPSpell] resolved", "block=" .. tostring(callContext.blockId), "requested=" .. tostring(params.spellId), "spellId=" .. tostring(spellId))
                if tonumber(spellId) <= 0 then
                    local invalidMsg = "VP_CAST invalid_spell_id spellId=" .. VPValueToString(spellId)
                    VPEmitUiLog(invalidMsg)
                    return false, invalidMsg
                end
                
                -- Add casting delay based on spell speed
                local castTime = SpellsInfo.GetSpellSpeed(spellId) * 1200
                local recoveryTime = SpellsInfo.GetRecoverySpeed() * 1200
                
                Debug.Print("Cast time: " .. castTime .. "ms, Recovery time: " .. recoveryTime .. "ms")
                        
                -- Create unique queue IDs for each timer
                local castQueueId = "cast_" .. spellId .. "_" .. tostring(Interface.TimeSinceLogin)
                local recoveryQueueId = "recovery_" .. spellId .. "_" .. tostring(Interface.TimeSinceLogin)
                
                -- Start casting the spell
                Debug.Print("Starting spell cast")
                local targetId = nil
                if params.target == "self" and WindowData and WindowData.PlayerStatus then
                    targetId = WindowData.PlayerStatus.PlayerId
                end
                local uoflowType = type(UOFlow)
                local spellTableType = uoflowType == "table" and type(UOFlow.Spell) or "<nil>"
                local castType = (uoflowType == "table" and spellTableType == "table") and type(UOFlow.Spell.cast) or "<nil>"
                local castSourceTag = VPBuildCastSourceTag("VisualProgramming.CastSpell", callContext, "UOFlow.Spell.cast")

                VPEmitUiLog(string.format(
                    "[VP_CAST] phase=node_before block=%s spell=%s type(UOFlow)=%s type(UOFlow.Spell)=%s type(UOFlow.Spell.cast)=%s source=%s",
                    VPValueToString(callContext.blockId),
                    VPValueToString(spellId),
                    VPValueToString(uoflowType),
                    VPValueToString(spellTableType),
                    VPValueToString(castType),
                    VPValueToString(castSourceTag)))

                local castOk = false
                local castResult1 = nil
                local castResult2 = nil
                local usedOnId = false

                castOk, castResult1, castResult2, usedOnId =
                    VPCastSpell(spellId, "VisualProgramming.CastSpell", targetId, callContext)

                local castErrorText = nil
                if not castOk then
                    castErrorText = VPValueToString(castResult2 or castResult1 or "cast_failed")
                end

                VPEmitUiLog(string.format(
                    "[VP_CAST] phase=node_after block=%s spell=%s ok=%s ret1=%s err=%s ret2=%s",
                    VPValueToString(callContext.blockId),
                    VPValueToString(spellId),
                    VPValueToString(castOk),
                    VPValueToString(castResult1),
                    VPValueToString(castErrorText),
                    VPValueToString(castResult2)))

                VPNativeLog("[VPSpell] execute result",
                    "block=" .. tostring(callContext.blockId),
                    "spellId=" .. tostring(spellId),
                    "ok=" .. tostring(castOk),
                    "result1=" .. tostring(castResult1),
                    "result2=" .. tostring(castResult2),
                    "error=" .. tostring(castErrorText),
                    "usedOnId=" .. tostring(usedOnId))
                if not castOk then
                    local failMsg = VPValueToString(castResult2 or castResult1 or "cast_failed")
                    VPEmitUiLog("VP_CAST failed block=" .. VPValueToString(callContext.blockId) .. " spellId=" .. VPValueToString(spellId) .. " err=" .. failMsg)
                    return false, failMsg
                end
                
                -- Queue cast timer
                Debug.Print("Starting cast sequence: " .. castTime .. "ms")
                WaitTimer(castTime, function()
                    Debug.Print("Cast time complete")
                    
                    -- Handle targeting
                    if params.target == "self" and not usedOnId then
                        Debug.Print("Targeting self with PlayerId: " .. tostring(WindowData.PlayerStatus.PlayerId))
                        GameData.UseRequests.UseTarget = WindowData.PlayerStatus.PlayerId
                        -- Add a small delay between setting target and handling targeting
                        WaitTimer(500, function()
                            HandleSingleLeftClkTarget(WindowData.PlayerStatus.PlayerId)
                            Debug.Print("Self-targeting complete")
                            
                            -- Queue recovery timer after targeting completes
                            Debug.Print("Queueing recovery: " .. recoveryTime .. "ms")
                            WaitTimer(recoveryTime, function()
                                Debug.Print("Recovery time complete - full sequence done")
                                VisualProgrammingInterface.ActionTimer:notifyCompletion()
                                return true -- Complete recovery timer
                            end, recoveryQueueId)
                            
                            return true
                        end, castQueueId .. "_target")
                    else
                        -- If not self-targeting, queue recovery timer immediately
                        Debug.Print("Queueing recovery: " .. recoveryTime .. "ms")
                        WaitTimer(recoveryTime, function()
                            Debug.Print("Recovery time complete - full sequence done")
                            VisualProgrammingInterface.ActionTimer:notifyCompletion()
                            return true -- Complete recovery timer
                        end, recoveryQueueId)
                    end
                    
                    return true
                end, castQueueId)
                
                return false -- Keep execution system waiting
            end
            VPNativeLog("[VPSpell] spell id not found", "block=" .. tostring(callContext.blockId), tostring(params.spellId))
            VPEmitUiLog("VP_CAST invalid_spell_id spellId=" .. VPValueToString(spellId or 0))
            return false, "invalid_spell_id"
        end
    })

    -- Magic Actions
    VisualProgrammingInterface.Actions:register({
        name = "Heal Self",
        description = L"Cast healing on yourself",
        category = Categories.MAGIC,
        icon = { texture = "icon856001", x = 5, y = 5 },
        params = {},
        execute = function(params)
            local spellId = 29 -- Heal spell ID
            local callContext = VPBuildCallContext(params, "VisualProgramming.HealSelf")
            
            -- Start casting the spell
            local targetId = nil
            if WindowData and WindowData.PlayerStatus then
                targetId = WindowData.PlayerStatus.PlayerId
            end
            local castOk, castResult1, castResult2, usedOnId = VPCastSpell(spellId, "VisualProgramming.HealSelf", targetId, callContext)
            VPNativeLog("[VPSpell] heal execute result",
                "block=" .. tostring(callContext.blockId),
                "spellId=" .. tostring(spellId),
                "ok=" .. tostring(castOk),
                "result1=" .. tostring(castResult1),
                "result2=" .. tostring(castResult2),
                "usedOnId=" .. tostring(usedOnId))
            if not castOk or castResult1 == false then
                local failMsg = VPValueToString(castResult2 or castResult1 or "cast_failed")
                VPEmitUiLog("VP_CAST failed block=" .. VPValueToString(callContext.blockId) .. " spellId=" .. VPValueToString(spellId) .. " err=" .. failMsg)
                return false, failMsg
            end
            
            -- Add casting delay based on spell speed
            local castTime = SpellsInfo.GetSpellSpeed(spellId) * 1000
            local recoveryTime = SpellsInfo.GetRecoverySpeed() * 1000
            
            -- Create unique queue IDs for each timer
            local castQueueId = "cast_heal_" .. tostring(Interface.TimeSinceLogin)
            local recoveryQueueId = "recovery_heal_" .. tostring(Interface.TimeSinceLogin)
            
            -- Queue cast timer
            Debug.Print("Starting cast sequence: " .. castTime .. "ms")
            WaitTimer(castTime, function()
                Debug.Print("Cast time complete")
                
                -- Set target and handle targeting in sequence
                if not usedOnId then
                    GameData.UseRequests.UseTarget = WindowData.PlayerStatus.PlayerId
                    -- Add a small delay between setting target and handling targeting
                    WaitTimer(50, function()
                        HandleSingleLeftClkTarget(WindowData.PlayerStatus.PlayerId)
                        Debug.Print("Self-targeting complete")
                        
                        -- Queue recovery timer after targeting completes
                        Debug.Print("Queueing recovery: " .. recoveryTime .. "ms")
                        WaitTimer(recoveryTime, function()
                            Debug.Print("Recovery time complete")
                            VisualProgrammingInterface.ActionTimer:notifyCompletion()
                            return true -- Complete recovery timer
                        end, recoveryQueueId)
                        
                        return true
                    end, castQueueId .. "_target")
                else
                    Debug.Print("Skipping manual target (CastSpellOnId path)")
                    Debug.Print("Queueing recovery: " .. recoveryTime .. "ms")
                    WaitTimer(recoveryTime, function()
                        Debug.Print("Recovery time complete")
                        VisualProgrammingInterface.ActionTimer:notifyCompletion()
                        return true -- Complete recovery timer
                    end, recoveryQueueId)
                end
                
                return true
            end, castQueueId)
            
            return false -- Keep execution system waiting
        end
    })

    -- Combat Actions
    VisualProgrammingInterface.Actions:register({
        name = "Bandage Self",
        description = L"Use bandages on yourself",
        category = Categories.COMBAT,
        icon = { texture = "icon000646", x = 5, y = 5 },
        params = {
            CreateParameter("wait", "boolean", true)
        },
        execute = function(params)
            UserActionUseItem() -- Assumes bandages are selected
            
            if params.wait then
                local queueId = "bandage_" .. tostring(Interface.TimeSinceLogin)
                WaitTimer(10000, function()
                    Debug.Print("Bandage timer complete")
                    VisualProgrammingInterface.ActionTimer:notifyCompletion()
                    return true
                end, queueId)
                
                return false -- Keep execution system waiting
            end
            
            return true -- If not waiting, complete immediately
        end
    })

    -- Skills Actions
    VisualProgrammingInterface.Actions:register({
        name = "Hide",
        description = L"Attempt to hide",
        category = Categories.SKILLS,
        icon = { texture = "icon000667", x = 5, y = 5 },
        params = {
            CreateParameter("retry", "boolean", false),
            CreateParameter("retryDelay", "number", 1000)
        },
        execute = function(params)
            UserActionHide()
            
            -- Create unique queue IDs for each timer
            local delayQueueId = "hide_delay_" .. tostring(Interface.TimeSinceLogin)
            local retryQueueId = "hide_retry_" .. tostring(Interface.TimeSinceLogin)
            
            -- Queue base delay timer
            Debug.Print("Starting base delay: 1000ms")
            WaitTimer(1000, function()
                Debug.Print("Hide base delay complete")
                
                if not params.retry then
                    VisualProgrammingInterface.ActionTimer:notifyCompletion()
                end
                
                return true -- Complete delay timer
            end, delayQueueId)
            
            -- Queue retry timer if enabled
            if params.retry then
                Debug.Print("Queueing retry delay: " .. params.retryDelay .. "ms")
                WaitTimer(params.retryDelay, function()
                    Debug.Print("Hide retry delay complete")
                    VisualProgrammingInterface.ActionTimer:notifyCompletion()
                    return true -- Complete retry timer
                end, retryQueueId)
            end
            
            return false -- Keep execution system waiting
        end
    })

    -- Skills Actions
    VisualProgrammingInterface.Actions:register({
        name = "Meditate",
        description = L"Meditate to recover mana",
        category = Categories.SKILLS,
        icon = { texture = "icon000640", x = 5, y = 5 },
        params = {
            CreateParameter("duration", "number", 5000),
            CreateParameter("targetMana", "number", 100)
        },
        execute = function(params)
            UserActionMeditate()
            
            -- Create unique queue IDs for each timer
            local delayQueueId = "meditate_delay_" .. tostring(Interface.TimeSinceLogin)
            local durationQueueId = "meditate_duration_" .. tostring(Interface.TimeSinceLogin)
            
            -- Queue base delay timer
            Debug.Print("Starting base delay: 1000ms")
            WaitTimer(1000, function()
                Debug.Print("Meditate base delay complete")
                return true -- Complete delay timer
            end, delayQueueId)
            
            -- Queue duration timer
            Debug.Print("Queueing meditation duration: " .. params.duration .. "ms")
            WaitTimer(params.duration, function()
                Debug.Print("Meditation duration complete")
                VisualProgrammingInterface.ActionTimer:notifyCompletion()
                return true -- Complete duration timer
            end, durationQueueId)
            
            return false -- Keep execution system waiting
        end
    })

    -- General Actions
    VisualProgrammingInterface.Actions:register({
        name = "Wait",
        description = L"Wait for specified time",
        category = Categories.GENERAL,
        icon = { texture = "icon000623", x = 5, y = 5 },
        params = {
            CreateParameter("time", "number", 1000)
        },
        validate = function(params)
            local time = tonumber(params.time)
            return time and time >= 0 and time <= 10000
        end,
        execute = function(params)
            local queueId = "wait_" .. tostring(Interface.TimeSinceLogin)
            WaitTimer(params.time, function()
                Debug.Print("Wait timer complete")
                VisualProgrammingInterface.ActionTimer:notifyCompletion()
                return true
            end, queueId)
            return false -- Keep execution system waiting
        end
    })

    Debug.Print("Block types initialized")
end

-- Helper functions for block creation
function VisualProgrammingInterface.GetBlockIcon(blockType)
    local action = VisualProgrammingInterface.Actions:get(blockType)
    if not action or not action.icon then
        return { texture = "icon100121", x = 5, y = 5 }
    end
    
    return action.icon
end

function VisualProgrammingInterface.UpdateBlockIcon(iconWindow, blockType)
    if not DoesWindowNameExist(iconWindow) then
        Debug.Print("Error: Icon window does not exist: " .. iconWindow)
        return false
    end

    local icon = VisualProgrammingInterface.GetBlockIcon(blockType)
    
    -- Set window properties first
    WindowSetDimensions(iconWindow, 50, 50)
    WindowSetLayer(iconWindow, Window.Layers.POPUP)
    WindowSetShowing(iconWindow, true)
    
    -- Then set the texture
    Debug.Print("Setting texture for " .. iconWindow .. ": " .. icon.texture)
    ButtonSetTexture(iconWindow, InterfaceCore.ButtonStates.STATE_NORMAL, icon.texture, icon.x, icon.y)
    ButtonSetTexture(iconWindow, InterfaceCore.ButtonStates.STATE_NORMAL_HIGHLITE, icon.texture, icon.x, icon.y)
    ButtonSetTexture(iconWindow, InterfaceCore.ButtonStates.STATE_PRESSED, icon.texture, icon.x, icon.y)
    ButtonSetTexture(iconWindow, InterfaceCore.ButtonStates.STATE_PRESSED_HIGHLITE, icon.texture, icon.x, icon.y)
    
    return true
end

function VisualProgrammingInterface.GetBlockDescription(blockType)
    local action = VisualProgrammingInterface.Actions:get(blockType)
    return action and action.description or L"New action block"
end

-- Function to create and display a block
function VisualProgrammingInterface.CreateBlock(type, index)
    -- Verify action exists
    local action = VisualProgrammingInterface.Actions:get(type)
    if not action then
        Debug.Print("Error: Unknown action type: " .. type)
        return nil
    end
    Debug.Print("Creating block of type: " .. type .. " at index: " .. index)
    
    -- Get scroll child window name
    local scrollChild = "VisualProgrammingInterfaceWindowScrollWindowScrollChild"
    if not DoesWindowNameExist(scrollChild) then
        Debug.Print("Scroll child window does not exist")
        return nil
    end
    
    -- Create block in manager
    local block = VisualProgrammingInterface.manager:createBlock(type, 0, index * 80)
    local blockName = "Block" .. block.id
    Debug.Print("Block name: " .. blockName)
    block.windowName = blockName -- Store the window name for later reference
    
    -- Create block window
    if not DoesWindowNameExist(blockName) then
        Debug.Print("Creating window from template")
        CreateWindowFromTemplate(blockName, "BlockTemplate", "VisualProgrammingInterfaceWindowScrollWindowScrollChild")
        
        -- Ensure window exists before proceeding
        if not DoesWindowNameExist(blockName) then
            Debug.Print("Error: Block window not created: " .. blockName)
            return
        end

        -- Set dimensions and position
        WindowSetDimensions(blockName, 380, 50)
        WindowClearAnchors(blockName)
        WindowAddAnchor(blockName, "topleft", "VisualProgrammingInterfaceWindowScrollWindowScrollChild", "topleft", 0, index * 80)
        
        -- Initialize block with default parameters
        local defaultParams = VisualProgrammingInterface.Actions:getDefaultParams(type)
        if defaultParams then
            block.params = defaultParams
        end
        
        -- Set block name and description using Block methods
        local desc = block:getDescription()
        LabelSetText(blockName .. "Name", StringToWString(desc))
        LabelSetText(blockName .. "Description", StringToWString(desc))
        
        -- Update scroll child height
        local scrollChild = "VisualProgrammingInterfaceWindowScrollWindowScrollChild"
        if DoesWindowNameExist(scrollChild) then
            local _, height = WindowGetDimensions(scrollChild)
            local newHeight = math.max(height, (index + 1) * 80)
            WindowSetDimensions(scrollChild, 840, newHeight)
            Debug.Print("Updated scroll child height to: " .. tostring(newHeight))
        else
            Debug.Print("Warning: Scroll child window not found when updating height")
        end
        
        -- Set window properties
        WindowSetLayer(blockName, Window.Layers.DEFAULT)
        WindowSetShowing(blockName, true)
        WindowSetAlpha(blockName, 1.0)
        
        -- Set layers for child windows and ensure proper visibility
        if DoesWindowNameExist(blockName .. "Name") then
            WindowSetLayer(blockName .. "Name", Window.Layers.DEFAULT)
            WindowSetShowing(blockName .. "Name", true)
        end
        if DoesWindowNameExist(blockName .. "Description") then
            WindowSetLayer(blockName .. "Description", Window.Layers.DEFAULT)
            WindowSetShowing(blockName .. "Description", true)
        end
        
        -- Set block icon using helper function
        local iconWindow = blockName .. "Icon"
        Debug.Print("Setting icon for window: " .. iconWindow)
        if not VisualProgrammingInterface.UpdateBlockIcon(iconWindow, type) then
            -- List all windows to help debug
            Debug.Print("Listing all child windows of " .. blockName .. ":")
            local children = WindowGetChildren(blockName)
            if children then
                for _, child in ipairs(children) do
                    Debug.Print("Child window: " .. child)
                end
            end
            return
        end
        
        Debug.Print("Block created successfully")
    else
        Debug.Print("Block window already exists: " .. blockName)
    end
    
    return block
end
