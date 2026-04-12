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

local function ResolveNativeBridgeTableRoot()
    local bridge = nil

    if type(__uow_native_bridge_v1) == "table" then
        bridge = __uow_native_bridge_v1
    end

    if type(bridge) ~= "table" and type(_G) == "table" then
        bridge = rawget(_G, "__uow_native_bridge_v1")
    end

    if type(bridge) ~= "table" and type(getfenv) == "function" then
        local env = getfenv(1)
        if type(env) == "table" then
            bridge = rawget(env, "__uow_native_bridge_v1")
            if type(bridge) ~= "table" and type(env._G) == "table" then
                bridge = rawget(env._G, "__uow_native_bridge_v1")
            end
        end
    end

    if type(bridge) ~= "table" and type(uow) == "table" then
        bridge = rawget(uow, "__native_bridge_v1")
    end

    return bridge
end

local function ResolveNativeLog()
    local bridge = ResolveNativeBridgeTableRoot()
    local bridgeDebug = type(bridge) == "table" and rawget(bridge, "debug") or nil
    if type(bridgeDebug) == "function" then
        return bridgeDebug
    end
    if type(_G) == "table" then
        local rawNativeLog = rawget(_G, "__uow_debug_log_v1")
        if type(rawNativeLog) == "function" then
            return rawNativeLog
        end
    end
    if type(__uow_debug_log_v1) == "function" then
        return __uow_debug_log_v1
    end
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

local g_vpDebugPrintTeeInstalled = false
local g_vpDebugPrintForwarding = false
local g_vpRunSequence = 0

local function VPGetActiveRunId()
    if type(_G) == "table" then
        local runId = rawget(_G, "__uow_vp_active_run_id")
        if runId ~= nil then
            return tostring(runId)
        end
    end
    return nil
end

local function VPSetActiveRunId(runId)
    if type(_G) ~= "table" then
        return
    end
    if runId == nil then
        rawset(_G, "__uow_vp_active_run_id", nil)
    else
        rawset(_G, "__uow_vp_active_run_id", tostring(runId))
    end
end

local function VPBuildDllLogLine(message)
    local runId = VPGetActiveRunId()
    local prefix = "[LUA]"
    if type(runId) == "string" and runId ~= "" then
        prefix = prefix .. "[VP run=" .. runId .. "]"
    end
    return prefix .. " " .. VPValueToString(message)
end

local function VPForwardToDllLog(message)
    if g_vpDebugPrintForwarding then
        return nil
    end

    local logFn = ResolveNativeLog()
    if type(logFn) ~= "function" then
        return nil
    end

    g_vpDebugPrintForwarding = true
    local result = logFn(VPBuildDllLogLine(message))
    g_vpDebugPrintForwarding = false
    return result
end

local function VPInstallDebugPrintTee()
    if g_vpDebugPrintTeeInstalled then
        return
    end
    if type(_G) == "table" and rawget(_G, "__UOW_VP_DEBUG_PRINT_TEE_INSTALLED") then
        g_vpDebugPrintTeeInstalled = true
        return
    end
    if type(Debug) ~= "table" or type(Debug.Print) ~= "function" then
        return
    end

    local originalPrint = Debug.Print
    Debug.Print = function(message, ...)
        VPForwardToDllLog(message)
        return originalPrint(message, ...)
    end

    g_vpDebugPrintTeeInstalled = true
    if type(_G) == "table" then
        rawset(_G, "__UOW_VP_DEBUG_PRINT_TEE_INSTALLED", true)
    end
    VPForwardToDllLog("[LUA_TEE] Debug.Print -> DLL log")
end

local g_vpNativeHandles = {
    getter = nil,
    getter_name = nil,
    getter_identity = nil,
    getter_what = nil,
    vp_cast = nil,
    vp_cast_tag = nil,
    vp_cast_identity = nil,
    vp_ping = nil,
    vp_ping_tag = nil,
    vp_ping_identity = nil,
}

local VP_NATIVE_BRIDGE_NAME = "__uow_native_bridge_v1"
local VP_NATIVE_GETTER_NAME = "__uow_native_get_v1"
local VP_NATIVE_IS_CFUNC_NAME = "__uow_is_cfunc_v1"
local VP_NATIVE_CALL_CAST_NAME = "__uow_call_cast_v1"
local VP_NATIVE_HEALTH_NAME = "__uow_bridge_health_v1"
local VP_NATIVE_CAST_NAME = "__uow_vp_cast_v1"
local VP_NATIVE_PING_NAME = "__uow_vp_ping_v1"
local VP_NATIVE_CONTEXT_TOKEN_NAME = "__uow_context_token_v1"

local function VPGetFunctionWhat(fn)
    local what = "<nil>"
    if type(fn) == "function" and type(debug) == "table" and type(debug.getinfo) == "function" then
        local info = debug.getinfo(fn)
        if type(info) == "table" then
            what = VPValueToString(info.what)
        end
    end
    return what
end

local function VPResolveNativeBridgeTable()
    local bridge = ResolveNativeBridgeTableRoot()
    if type(bridge) ~= "table" then
        return nil, "native_bridge_missing name=" .. VP_NATIVE_BRIDGE_NAME
    end

    return bridge, nil
end

local function VPResolveDirectNativeFunction(name)
    local bridge, bridgeErr = VPResolveNativeBridgeTable()
    if type(bridge) ~= "table" then
        return nil, nil, bridgeErr
    end

    local fieldName = nil
    if name == VP_NATIVE_GETTER_NAME then
        fieldName = "get"
    elseif name == VP_NATIVE_HEALTH_NAME then
        fieldName = "health"
    elseif name == VP_NATIVE_CAST_NAME then
        fieldName = "vp_cast"
    elseif name == VP_NATIVE_PING_NAME then
        fieldName = "vp_ping"
    elseif name == "__uow_debug_log_v1" then
        fieldName = "debug"
    end

    if type(fieldName) ~= "string" then
        return nil, bridge, "native_bridge_field_unknown name=" .. VPValueToString(name)
    end

    local fn = rawget(bridge, fieldName)
    if type(fn) ~= "function" then
        return nil, bridge, "native_bridge_field_missing field=" .. VPValueToString(fieldName)
    end

    return fn, bridge, nil
end

local function VPGetNativeContextToken()
    local token = nil
    local bridge = nil
    bridge = VPResolveNativeBridgeTable()
    if type(bridge) == "table" then
        token = rawget(bridge, "context_token")
    end
    if token == nil then
        if type(_G) == "table" then
            token = rawget(_G, VP_NATIVE_CONTEXT_TOKEN_NAME)
        end
    end
    if token == nil then
        token = __uow_context_token_v1
    end
    return token
end

local function VPResolveNativeGetter()
    if type(g_vpNativeHandles.getter) == "function" then
        return g_vpNativeHandles.getter, nil
    end

    local getter, _, getterErr = VPResolveDirectNativeFunction(VP_NATIVE_GETTER_NAME)

    if type(getter) ~= "function" then
        return nil, getterErr or ("native_getter_missing name=" .. VP_NATIVE_GETTER_NAME)
    end

    local getterWhat = VPGetFunctionWhat(getter)
    g_vpNativeHandles.getter = getter
    g_vpNativeHandles.getter_name = VP_NATIVE_GETTER_NAME
    g_vpNativeHandles.getter_identity = tostring(getter)
    g_vpNativeHandles.getter_what = getterWhat
    return getter, nil
end

local function VPResolveBridgeHealthFunction()
    local fn = nil
    if type(_G) == "table" then
        fn = rawget(_G, VP_NATIVE_HEALTH_NAME)
    end
    if type(fn) == "function" then
        return fn, "global", nil
    end

    local bridgeFn, _, bridgeErr = VPResolveDirectNativeFunction(VP_NATIVE_HEALTH_NAME)
    if type(bridgeFn) == "function" then
        return bridgeFn, "bridge", nil
    end

    return nil, nil, bridgeErr or ("bridge_health_missing name=" .. VP_NATIVE_HEALTH_NAME)
end

local function VPInvokeBridgeHealth(reason)
    local healthFn, healthSource, healthErr = VPResolveBridgeHealthFunction()
    if type(healthFn) ~= "function" then
        return false, healthErr or ("bridge_health_missing name=" .. VP_NATIVE_HEALTH_NAME), healthSource
    end

    local ok, msg = healthFn(reason)
    VPNativeLog("[VPBridge] health",
        "reason=" .. VPValueToString(reason),
        "source=" .. VPValueToString(healthSource),
        "ok=" .. VPValueToString(ok),
        "msg=" .. VPValueToString(msg))
    Debug.Print(string.format(
        "[VPBridge] health reason=%s source=%s ok=%s msg=%s",
        VPValueToString(reason),
        VPValueToString(healthSource),
        VPValueToString(ok),
        VPValueToString(msg)))
    return ok, msg, healthSource
end

local function VPCheckBridgeIntegrity(reason)
    local healthOk, healthTag, healthSource = VPInvokeBridgeHealth(reason)
    local bridge, bridgeErr = VPResolveNativeBridgeTable()
    if type(bridge) ~= "table" then
        return false, bridgeErr or "native_bridge_missing", nil, nil, nil, nil, healthTag, healthSource
    end

    local castFn = rawget(bridge, "vp_cast")
    local getFn = rawget(bridge, "get")
    if type(castFn) ~= "function" then
        return false, "bridge_drift_detected vp_cast_type=" .. VPValueToString(type(castFn)),
            bridge, nil, getFn, nil, healthTag, healthSource
    end
    if type(getFn) ~= "function" then
        return false, "bridge_drift_detected get_type=" .. VPValueToString(type(getFn)),
            bridge, castFn, nil, nil, healthTag, healthSource
    end

    local expectedFn, expectedTag = getFn("vp_cast")
    local expectedPrefix = "vp_cast:cfn="
    if type(expectedFn) ~= "function" or type(expectedTag) ~= "string"
        or string.find(expectedTag, expectedPrefix, 1, true) == nil then
        return false, "bridge_drift_detected getter_fn=" .. VPValueToString(expectedFn)
            .. " getter_tag=" .. VPValueToString(expectedTag),
            bridge, castFn, getFn, nil, healthTag, healthSource
    end

    local bridgeIdentity = tostring(castFn)
    local getterIdentity = tostring(expectedFn)
    VPNativeLog("[VPBridge] integrity",
        "reason=" .. VPValueToString(reason),
        "bridgeFn=" .. VPValueToString(bridgeIdentity),
        "getterFn=" .. VPValueToString(getterIdentity),
        "healthTag=" .. VPValueToString(healthTag),
        "expectedTag=" .. VPValueToString(expectedTag))

    if healthOk ~= true then
        return false, "bridge_drift_detected health_source=" .. VPValueToString(healthSource)
            .. " health_tag=" .. VPValueToString(healthTag),
            bridge, castFn, getFn, expectedTag, healthTag, healthSource
    end

    if type(healthTag) == "string" and healthTag ~= "" and healthTag ~= expectedTag then
        return false, "bridge_drift_detected bridge_tag=" .. VPValueToString(healthTag)
            .. " getter_tag=" .. VPValueToString(expectedTag)
            .. " bridgeFn=" .. VPValueToString(bridgeIdentity)
            .. " getterFn=" .. VPValueToString(getterIdentity),
            bridge, castFn, getFn, expectedTag, healthTag, healthSource
    end

    return true, nil, bridge, castFn, getFn, expectedTag, healthTag, healthSource
end

local function VPGetCachedNativeHandle(key)
    local cachedFn = g_vpNativeHandles[key]
    local cachedTag = g_vpNativeHandles[key .. "_tag"]
    local cachedIdentity = g_vpNativeHandles[key .. "_identity"]
    if type(cachedFn) == "function" then
        return cachedFn, cachedTag, cachedIdentity, nil
    end

    local getter, getterErr = VPResolveNativeGetter()
    if type(getter) ~= "function" then
        return nil, nil, nil, getterErr or "native_getter_missing name=" .. VP_NATIVE_GETTER_NAME
    end

    local fn, tag = getter(key)
    local fnWhat = VPGetFunctionWhat(fn)
    local expectedTag = tostring(key) .. ":cfn="
    if type(fn) ~= "function" or type(tag) ~= "string" or string.find(tag, expectedTag, 1, true) == nil then
        return nil, nil, nil, "native_getter_mismatch key=" .. VPValueToString(key)
            .. " fn=" .. VPValueToString(fn)
            .. " what=" .. VPValueToString(fnWhat)
            .. " tag=" .. VPValueToString(tag)
            .. " expectedTag=" .. VPValueToString(expectedTag)
    end

    g_vpNativeHandles[key] = fn
    g_vpNativeHandles[key .. "_tag"] = tag
    g_vpNativeHandles[key .. "_identity"] = tostring(fn)
    return fn, tag, g_vpNativeHandles[key .. "_identity"], nil
end

local function VPEmitUiLog(message)
    local text = VPValueToString(message)
    VPNativeLog(text)
    if type(Debug) == "table" and type(Debug.Print) == "function" then
        Debug.Print(text)
    end
end

VPInstallDebugPrintTee()

if type(_G) == "table" and not rawget(_G, "__UOW_VP_MARKER_DEBUGTEE_V1") then
    rawset(_G, "__UOW_VP_MARKER_DEBUGTEE_V1", true)
    local marker = "[VP_MARKER] VisualProgrammingTypes.lua build=debugtee_v1 loaded"
    VPNativeLog(marker)
    if type(Debug) == "table" and type(Debug.Print) == "function" then
        Debug.Print(marker)
    end
end

local function VPNextRunId(blockId, blockType)
    g_vpRunSequence = g_vpRunSequence + 1
    local loginTick = Interface and Interface.TimeSinceLogin or 0
    return string.format(
        "%s-%s-%s-%s",
        VPValueToString(blockType or "vp"),
        VPValueToString(blockId),
        VPValueToString(loginTick),
        VPValueToString(g_vpRunSequence))
end

local function VPBuildCallContext(params, fallbackTag)
    local blockId = params and params.__vpBlockId or nil
    local blockType = params and params.__vpBlockType or nil
    local runId = params and params.__vpRunId or nil
    if not runId then
        runId = VPNextRunId(blockId, blockType or fallbackTag)
    end
    local executionTag = params and params.__vpExecutionTag or nil
    if not executionTag then
        executionTag = "VP:run=" .. tostring(runId) .. ":block=" .. tostring(blockId) .. ":type=" .. tostring(blockType or fallbackTag)
    end
    VPSetActiveRunId(runId)

    return {
        blockId = blockId,
        blockType = blockType,
        runId = runId,
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
        or string.find(label, "__uow_call_cast_v1", 1, true) ~= nil
        or string.find(label, "uow_vp_cast", 1, true) ~= nil
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
    local what = VPGetFunctionWhat(fn)

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

local function VPValidateNativeHandle(key, fn, expectedTag, expectedIdentity)
    if type(fn) ~= "function" then
        return false, "cast_helper_tampered key=" .. VPValueToString(key) .. " type=" .. VPValueToString(type(fn))
    end

    local what = VPGetFunctionWhat(fn)

    local expectedTagPrefix = VPValueToString(key) .. ":cfn="
    if type(expectedTag) ~= "string" or string.find(expectedTag, expectedTagPrefix, 1, true) == nil then
        return false, "cast_helper_tampered key=" .. VPValueToString(key)
            .. " tag=" .. VPValueToString(expectedTag)
            .. " expectedTag=" .. VPValueToString(expectedTagPrefix)
    end

    local currentIdentity = tostring(fn)
    if expectedIdentity and currentIdentity ~= expectedIdentity then
        return false, "cast_helper_tampered key=" .. VPValueToString(key)
            .. " identity=" .. VPValueToString(currentIdentity)
            .. " expected=" .. VPValueToString(expectedIdentity)
            .. " tag=" .. VPValueToString(expectedTag)
    end

    return true, nil
end

local function VPInvokeNativePing()
    local pingFn, pingBridge, pingBridgeErr = VPResolveDirectNativeFunction(VP_NATIVE_PING_NAME)
    local pingTag = nil
    local pingErr = pingBridgeErr
    local pingLabel = VP_NATIVE_PING_NAME .. "(direct)"
    if type(pingFn) == "function" then
        pingTag = "direct:" .. VPValueToString(tostring(pingFn))
    end

    if type(pingFn) ~= "function" then
        Debug.Print("[VP_PING] missing err=" .. VPValueToString(pingErr))
        return nil, pingErr
    end

    local pingResult = pingFn()
    VPNativeLog("[VP_PING] result",
        VPValueToString(pingResult),
        "helper=" .. pingLabel,
        "tag=" .. VPValueToString(pingTag),
        "bridge=" .. VPValueToString(pingBridge),
        "token=" .. VPValueToString(VPGetNativeContextToken()))
    Debug.Print("[VP_PING] result=" .. VPValueToString(pingResult))
    return pingResult, nil
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

local function VPResolveNativeGlobalFunction(name)
    if type(name) ~= "string" or name == "" then
        return nil, nil, "native_global_missing name=" .. VPValueToString(name)
    end

    local direct = nil
    if type(_G) == "table" then
        direct = rawget(_G, name)
    end
    if type(direct) ~= "function" then
        if name == VP_NATIVE_CALL_CAST_NAME and type(__uow_call_cast_v1) == "function" then
            direct = __uow_call_cast_v1
        elseif name == VP_NATIVE_IS_CFUNC_NAME and type(__uow_is_cfunc_v1) == "function" then
            direct = __uow_is_cfunc_v1
        end
    end
    if type(direct) == "function" then
        return direct, "direct", nil
    end

    local env = nil
    if type(getfenv) == "function" then
        env = getfenv(1)
    end

    local candidates = {
        { source = "_G", fn = VPLookupRawFunction(_G, name) },
        { source = "env", fn = VPLookupRawFunction(env, name) },
        { source = "env._G", fn = type(env) == "table" and VPLookupRawFunction(rawget(env, "_G"), name) or nil },
    }

    for _, candidate in ipairs(candidates) do
        if type(candidate.fn) == "function" then
            return candidate.fn, candidate.source, nil
        end
    end

    return nil, nil, "native_global_missing name=" .. VPValueToString(name)
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
    local castFn, castSource, castResolveErr = VPResolveNativeGlobalFunction(VP_NATIVE_CALL_CAST_NAME)
    local sourceTag = callContext.nativeSourceTag or tag
    local castLabel = VP_NATIVE_CALL_CAST_NAME .. "(" .. VPValueToString(castSource) .. ")"
    local candidateSummary = {
        VPDescribeCandidate(VP_NATIVE_CALL_CAST_NAME, castFn),
        "call_cast.err=" .. VPValueToString(castResolveErr),
        "call_cast.source=" .. VPValueToString(castSource),
        VPDescribeCandidate(castLabel, castFn),
    }

    VPNativeLog("[VPSpell] cast begin",
        tostring(tag),
        "spell=" .. tostring(spellId),
        "ctx=" .. tostring(callContext.executionTag),
        "source=" .. tostring(sourceTag),
        "targetId=" .. tostring(targetId),
        "call_cast_source=" .. tostring(castSource))
    VPNativeLog("[VPSpell] cast candidates", tostring(tag), table.concat(candidateSummary, " | "))
    Debug.Print("[VPSpell] cast candidates " .. table.concat(candidateSummary, " | "))
    VPLogSpellState(tag .. ":before", spellId)

    if type(castFn) ~= "function" then
        local missingMsg = castResolveErr or ("native_entry_missing name=" .. VP_NATIVE_CALL_CAST_NAME)
        VPEmitUiLog("VP_CAST " .. missingMsg)
        VPNativeLog("[VPSpell] cast fail",
            tostring(tag),
            missingMsg,
            "callCastSource=" .. VPValueToString(castSource))
        VPLogSpellState(tag .. ":after", spellId)
        return false, missingMsg, nil, false
    end

    local beforeState = VPSnapshotSpellState()
    local ok = false
    local result1 = nil
    local result2 = nil
    local errText = nil

    VPLogCastCall("before", tag, spellId, castLabel, callContext, nil, nil, nil, nil)
    local preCallMessage = "[VP_CALL] about to call " .. VPValueToString(VP_NATIVE_CALL_CAST_NAME)
        .. " spell=" .. VPValueToString(spellId)
        .. " source=" .. VPValueToString(sourceTag)
        .. " helper=" .. VPValueToString(castLabel)
        .. " fn=" .. VPValueToString(castFn)
    Debug.Print(preCallMessage)
    VPNativeLog(preCallMessage)
    ok, result1, result2, errText = VPInvokeFunction(castFn, spellId, sourceTag)
    local postCallMessage = "[VP_CALL] after call " .. VPValueToString(VP_NATIVE_CALL_CAST_NAME)
        .. " spell=" .. VPValueToString(spellId)
        .. " ok=" .. VPValueToString(ok)
        .. " ret1=" .. VPValueToString(result1)
        .. " ret2=" .. VPValueToString(result2)
        .. " err=" .. VPValueToString(errText)
    Debug.Print(postCallMessage)
    VPNativeLog(postCallMessage)

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
        "source=" .. tostring(sourceTag))
    Debug.Print(string.format(
        "[VPSpell] %s helper=%s ok=%s result1=%s result2=%s stateChanged=%s hardSuccess=%s source=%s",
        VPValueToString(tag),
        VPValueToString(castLabel),
        VPValueToString(ok),
        VPValueToString(result1),
        VPValueToString(result2),
        VPValueToString(stateChanged),
        VPValueToString(hardSuccess),
        VPValueToString(sourceTag)))

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
                callContext.nativeSourceTag = "VP_TEST_BUTTON"
                VPInvokeBridgeHealth("VP_CAST/node_before block="
                    .. VPValueToString(callContext.blockId)
                    .. " spell=" .. VPValueToString(spellId))

                VPEmitUiLog(string.format(
                    "[VP_CAST] phase=node_before block=%s spell=%s type(UOFlow)=%s type(UOFlow.Spell)=%s type(UOFlow.Spell.cast)=%s source=%s",
                    VPValueToString(callContext.blockId),
                    VPValueToString(spellId),
                    VPValueToString(uoflowType),
                    VPValueToString(spellTableType),
                    VPValueToString(castType),
                    VPValueToString(callContext.nativeSourceTag)))

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
