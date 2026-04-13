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
VisualProgrammingInterface.Actions.actions = VisualProgrammingInterface.Actions.actions or {}
VisualProgrammingInterface.Actions.registry = VisualProgrammingInterface.Actions.registry or {}
VisualProgrammingInterface.Actions.defaultParams = VisualProgrammingInterface.Actions.defaultParams or {}

function VisualProgrammingInterface.Actions:register(action)
    Debug.Print("Registering action: " .. action.name)
    self.actions[action.name] = action
end

function VisualProgrammingInterface.Actions:get(name)
    Debug.Print("Getting action: " .. name)
    return self.actions[name]
end

function VisualProgrammingInterface.Actions:validateParams(type, params)
    Debug.Print("Validating params for: " .. type)
    local action = self:get(type)
    if not action then
        Debug.Print("Action not found: " .. type)
        return false
    end
    if action.validate then
        local success = action.validate(params)
        Debug.Print("Validation " .. (success and "passed" or "failed"))
        return success
    end
    return true
end

function VisualProgrammingInterface.Actions:execute(type, params)
    Debug.Print("Executing action: " .. type)
    local action = self:get(type)
    if not action then
        Debug.Print("Action not found: " .. type)
        return false
    end
    local success = action.execute(params)
    Debug.Print("Action execution " .. (success and "succeeded" or "failed"))
    return success
end

local function VPUIEmitNativeLog(...)
    if type(UOWNativeLog) == "function" then
        UOWNativeLog(...)
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
    if VisualProgrammingInterface and VisualProgrammingInterface.Execution then
        VPUIEmitNativeLog("[VPUI] testFlow BEFORE")
        local success, results = VisualProgrammingInterface.Execution:testFlow()
        VPUIEmitNativeLog(
            "[VPUI] testFlow AFTER",
            "success=" .. tostring(success),
            "resultsType=" .. type(results))

        if success then
            if results.success then
                VPUIEmitNativeLog("[VPUI] results.success", "executionOrder=" .. table.concat(results.executionOrder or {}, ","))
                Debug.Print("Flow test completed successfully")
                Debug.Print("Execution order: " .. table.concat(results.executionOrder, ", "))
                
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
    WindowSetShowing("VisualProgrammingInterfaceWindow", true)
    -- Register update handlers
    RegisterEventHandler(SystemData.Events.UPDATE_PROCESSED, "VisualProgrammingInterface.Execution.OnUpdate")
    RegisterEventHandler(SystemData.Events.UPDATE_PROCESSED, "VisualProgrammingInterface.ActionTimer.OnUpdate")
end

-- Hide interface
function VisualProgrammingInterface.Hide()
    WindowSetShowing("VisualProgrammingInterfaceWindow", false)
    -- Unregister update handlers
    UnregisterEventHandler(SystemData.Events.UPDATE_PROCESSED, "VisualProgrammingInterface.Execution.OnUpdate")
    UnregisterEventHandler(SystemData.Events.UPDATE_PROCESSED, "VisualProgrammingInterface.ActionTimer.OnUpdate")
    
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
