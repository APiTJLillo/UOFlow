-- Main entry point for Visual Programming Interface
VisualProgrammingInterface = VisualProgrammingInterface or {}

-- Initialize Actions system
VisualProgrammingInterface.Actions = VisualProgrammingInterface.Actions or {}
VisualProgrammingInterface.Actions.categories = VisualProgrammingInterface.Actions.categories or {
    GENERAL = "General",
    MAGIC = "Magic",
    ITEMS = "Items",
    TARGETING = "Targeting",
    MOVEMENT = "Movement",
    COMBAT = "Combat",
    SKILLS = "Skills"
}
VisualProgrammingInterface.Actions.registry = VisualProgrammingInterface.Actions.registry or {}
VisualProgrammingInterface.Actions.defaultParams = VisualProgrammingInterface.Actions.defaultParams or {}

local function VPUIEmitNativeLog(...)
    if type(UOWNativeLog) == "function" then
        UOWNativeLog(...)
    end
end

local function VPUIJoinList(values)
    if type(values) ~= "table" then
        return ""
    end

    local parts = {}
    for i = 1, #values do
        parts[i] = tostring(values[i])
    end
    return table.concat(parts, ",")
end

local function VPUICollectBlocksInVisualOrder()
    local manager = VisualProgrammingInterface and VisualProgrammingInterface.manager or nil
    if type(manager) == "table" and type(manager.getBlocksInVisualOrder) == "function" then
        return manager:getBlocksInVisualOrder()
    end

    local ordered = {}
    if type(manager) == "table" and type(manager.blocks) == "table" then
        for _, block in pairs(manager.blocks) do
            if type(block) == "table" and block.id ~= nil then
                table.insert(ordered, block)
            end
        end
    end

    table.sort(ordered, function(a, b)
        local aRank = (type(a) == "table" and a.column == "right") and 1 or 0
        local bRank = (type(b) == "table" and b.column == "right") and 1 or 0
        if aRank ~= bRank then
            return aRank < bRank
        end

        local ay = tonumber(a and a.y) or 0
        local by = tonumber(b and b.y) or 0
        if ay ~= by then
            return ay < by
        end

        return (tonumber(a and a.id) or 0) < (tonumber(b and b.id) or 0)
    end)

    return ordered
end

local function VPUIStartDirectTestRun()
    local execution = VisualProgrammingInterface and VisualProgrammingInterface.Execution or nil
    local manager = VisualProgrammingInterface and VisualProgrammingInterface.manager or nil
    if type(execution) ~= "table" then
        return false, "execution_missing"
    end
    if type(manager) ~= "table" or type(manager.blocks) ~= "table" then
        return false, "manager_missing"
    end

    if type(execution.hardResetForTestRun) == "function" then
        execution:hardResetForTestRun()
    end

    local orderedBlocks = VPUICollectBlocksInVisualOrder()
    if type(UOWNativeLog) == "function" then
        UOWNativeLog("[VPUI] direct test queue", "count=" .. tostring(#orderedBlocks))
    end
    if #orderedBlocks == 0 then
        return false, "No executable blocks"
    end

    execution.blockStates = {}
    for id, _ in pairs(manager.blocks) do
        execution.blockStates[id] = VisualProgrammingInterface.Execution.BlockState.PENDING
    end

    if VisualProgrammingInterface.ActionTimer then
        VisualProgrammingInterface.ActionTimer.isWaiting = false
        VisualProgrammingInterface.ActionTimer.callback = nil
        VisualProgrammingInterface.ActionTimer.functionQueue = {}
        VisualProgrammingInterface.ActionTimer.currentQueueId = nil
        VisualProgrammingInterface.ActionTimer.isComplete = false
        VisualProgrammingInterface.ActionTimer.currentTime = 0
        VisualProgrammingInterface.ActionTimer.targetTime = 0
    end

    execution.executionQueue = {}
    for _, block in ipairs(orderedBlocks) do
        table.insert(execution.executionQueue, block)
    end
    execution.primingFirstBlock = false
    execution.isRunning = true
    execution.isPaused = false
    execution.currentBlock = nil
    execution.waitingForTimer = false
    execution.continueTimer = 0
    execution.pendingRawDispatch = nil
    execution.pendingCompletionWatch = nil

    local firstBlock = execution.executionQueue[1]
    if type(firstBlock) ~= "table" or firstBlock.id == nil then
        execution.executionQueue = {}
        execution.isRunning = false
        return false, "missing_first_block"
    end

    if type(UOWNativeLog) == "function" then
        UOWNativeLog("[VPUI] direct test armed",
            "block=" .. tostring(firstBlock.id),
            "type=" .. tostring(firstBlock.type),
            "queue=" .. tostring(#execution.executionQueue))
    end
    execution.continueTimer = execution.delay / 1000
    return true, {
        success = true,
        executionOrder = {},
        blocks = {}
    }
end

local function VPUIRegisterUpdateHandlers(reason)
    if VisualProgrammingInterface._updateHandlersRegistered then
        return
    end

    RegisterEventHandler(SystemData.Events.UPDATE_PROCESSED, "VisualProgrammingInterface.OnExecutionUpdate")
    RegisterEventHandler(SystemData.Events.UPDATE_PROCESSED, "VisualProgrammingInterface.OnActionTimerUpdate")
    VisualProgrammingInterface._updateHandlersRegistered = true

    if type(UOWNativeLog) == "function" then
        UOWNativeLog("[VPUI] update handlers registered", "reason=" .. tostring(reason))
    end
end

local function VPUIUnregisterUpdateHandlers(reason)
    if not VisualProgrammingInterface._updateHandlersRegistered then
        return
    end

    UnregisterEventHandler(SystemData.Events.UPDATE_PROCESSED, "VisualProgrammingInterface.OnExecutionUpdate")
    UnregisterEventHandler(SystemData.Events.UPDATE_PROCESSED, "VisualProgrammingInterface.OnActionTimerUpdate")
    VisualProgrammingInterface._updateHandlersRegistered = false

    if type(UOWNativeLog) == "function" then
        UOWNativeLog("[VPUI] update handlers unregistered", "reason=" .. tostring(reason))
    end
end

VisualProgrammingInterface.RegisterUpdateHandlers = VPUIRegisterUpdateHandlers
VisualProgrammingInterface.UnregisterUpdateHandlers = VPUIUnregisterUpdateHandlers

function VisualProgrammingInterface.OnExecutionUpdate(timePassed)
    if type(VisualProgrammingInterface.RefreshBlockViewportVisibility) == "function" then
        VisualProgrammingInterface.RefreshBlockViewportVisibility()
    end
    local execution = VisualProgrammingInterface.Execution
    if type(execution) ~= "table" or type(execution.OnUpdate) ~= "function" then
        return
    end
    execution.OnUpdate(execution, timePassed)
end

function VisualProgrammingInterface.OnActionTimerUpdate(timePassed)
    local timer = VisualProgrammingInterface.ActionTimer
    if type(timer) ~= "table" then
        return
    end

    if type(Timer) == "table" and type(Timer.OnUpdate) == "function" then
        Timer.OnUpdate(timer, timePassed)
        return
    end

    if type(timer.OnUpdate) == "function" then
        timer.OnUpdate(timer, timePassed)
    end
end

-- Handle test flow button click
function OnTestFlowClick()
    -- Forward to the interface handler
    if Debug and type(Debug.Print) == "function" then
        Debug.Print("[VPUI] Test clicked")
    end
    VPUIEmitNativeLog("[VPUI] OnTestFlowClick ENTER")
    if type(UOWInstallLuaSpellWrappers) == "function" then
        UOWInstallLuaSpellWrappers()
    end
    if type(UOWInstallLuaMovementWrappers) == "function" then
        UOWInstallLuaMovementWrappers()
    end
    if VisualProgrammingInterface and type(VisualProgrammingInterface.EnsureStarterBlocks) == "function" then
        VisualProgrammingInterface.EnsureStarterBlocks("test_click")
    end
    if VisualProgrammingInterface and VisualProgrammingInterface.Execution then
        VPUIEmitNativeLog("[VPUI] testFlow BEFORE")
        local success, results = VPUIStartDirectTestRun()
        VPUIEmitNativeLog(
            "[VPUI] testFlow AFTER",
            "success=" .. tostring(success),
            "resultsType=" .. type(results))

        if success then
            if results.success then
                VPUIEmitNativeLog("[VPUI] results.success", "executionOrder=" .. VPUIJoinList(results.executionOrder))
                Debug.Print("Flow test completed successfully")
                Debug.Print("Execution order: " .. VPUIJoinList(results.executionOrder))
                
                -- Print details for each block
                for id, block in pairs(results.blocks) do
                    Debug.Print(string.format("Block %s (%s): %s", 
                        id,
                        block.type,
                        block.state or "unknown state"
                    ))
                end
            else
                VPUIEmitNativeLog("[VPUI] flow test failed", tostring(results.error))
                Debug.Print("Flow test failed: " .. (results.error or "Unknown error"))
            end
        else
            VPUIEmitNativeLog("[VPUI] could not start flow test", tostring(results))
            Debug.Print("Could not start flow test: " .. (results or "Unknown error"))
        end
    else
        VPUIEmitNativeLog("[VPUI] execution system missing")
        Debug.Print("Error: Execution system not initialized")
    end
end

-- Store reference in interface table for internal use
VisualProgrammingInterface.OnTestFlowClick = OnTestFlowClick

-- Global initialization - forwards to core initialization
function Initialize()
    Debug.Print("Global initialization of Visual Programming Interface")
    
    -- Initialize block types
    if type(VisualProgrammingInterface.InitializeBlockTypes) == "function" then
        Debug.Print("Initializing block types")
        VisualProgrammingInterface.InitializeBlockTypes()
    else
        Debug.Print("Warning: InitializeBlockTypes not available")
    end
    
    -- Initialize core systems
    if type(VisualProgrammingInterface.Initialize) == "function" then
        Debug.Print("Initializing core systems")
        VisualProgrammingInterface.Initialize()
    else
        Debug.Print("Warning: Core initialization not available")
    end
end

function VisualProgrammingInterface.Show()
    local windowName = "VisualProgrammingInterfaceWindow"
    local exists = DoesWindowNameExist(windowName)
    local showing = exists and WindowGetShowing(windowName) or false
    if type(UOWNativeLog) == "function" then
        UOWNativeLog("[VPUI] show enter",
            "exists=" .. tostring(exists),
            "showing=" .. tostring(showing),
            "manager=" .. tostring(type(VisualProgrammingInterface.manager)))
    end

    if exists and not showing then
        WindowSetShowing(windowName, true)
    end

    VisualProgrammingInterface._starterSeedRequested = true
    VPUIRegisterUpdateHandlers("show")

    if type(VisualProgrammingInterface.EnsureStarterBlocks) == "function" then
        local seeded = VisualProgrammingInterface.EnsureStarterBlocks("show")
        if type(UOWNativeLog) == "function" then
            UOWNativeLog("[VPUI] show seed",
                "seeded=" .. tostring(seeded),
                "existing=" .. tostring(type(VisualProgrammingInterface.GetManagerBlockCount) == "function"
                    and VisualProgrammingInterface.GetManagerBlockCount() or 0))
        end
    end
end

-- Hide interface
function VisualProgrammingInterface.Hide()
    WindowSetShowing("VisualProgrammingInterfaceWindow", false)
    VPUIUnregisterUpdateHandlers("hide")
    
    -- Clean up timer state
    if VisualProgrammingInterface.ActionTimer then
        VisualProgrammingInterface.ActionTimer:reset()
    end
    
    -- Clean up execution state
    if VisualProgrammingInterface.Execution then
        VisualProgrammingInterface.Execution:stop()
    end
end

-- Triggers system
VisualProgrammingInterface.Triggers = {
    triggers = {},
    triggerStates = {}
}

function VisualProgrammingInterface.Triggers:register(trigger)
    if not trigger.name then
        Debug.Print("Trigger definition must have a name")
        return false
    end
    Debug.Print("Registering trigger: " .. trigger.name)
    self.triggers[trigger.name] = trigger
    self.triggerStates[trigger.name] = {}
    return true
end

function VisualProgrammingInterface.Triggers:check()
    for name, trigger in pairs(self.triggers) do
        local result = trigger.check()
        if result then
            if trigger.config and trigger.config.unique then
                if self.triggerStates[name][result] then
                    Debug.Print("Trigger already activated for unique instance: " .. name)
                    return false, nil
                end
                self.triggerStates[name][result] = true
            end
            Debug.Print("Trigger activated: " .. name)
            return true, name, result
        end
    end
    return false, nil
end

-- Add support for more complex conditional logic and loops
function VisualProgrammingInterface.AddConditionalLogic()
    -- Placeholder for adding complex conditional logic
end

function VisualProgrammingInterface.AddLoops()
    -- Placeholder for adding loop support
end

-- Enhance user interface with more intuitive controls and visual feedback
function VisualProgrammingInterface.EnhanceUI()
    -- Placeholder for enhancing UI
end
