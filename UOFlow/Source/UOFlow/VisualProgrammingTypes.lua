-- Block type definitions and utilities

-- Timer system with function queue
VisualProgrammingInterface.ActionTimer = {
    currentTime = 0,
    targetTime = 0,
    isWaiting = false,
    callback = nil,
    functionQueue = {},
    currentQueueId = nil,
    isComplete = false,
    
    -- New completion callback system
    completionCallbacks = {},
    
    -- Register a completion callback
    registerCompletionCallback = function(self, callbackName, callback)
        self.completionCallbacks[callbackName] = callback
    end,
    
    -- Notify all registered completion callbacks
    notifyCompletion = function(self)
        for _, callback in pairs(self.completionCallbacks) do
            pcall(callback)
        end
    end,
    
    -- Clean up timer state
    reset = function(self)
        self.isWaiting = false
        self.callback = nil
        self.functionQueue = {}
        self.currentQueueId = nil
        self.isComplete = false
        self.currentTime = 0
        self.targetTime = 0
    end
}

function VisualProgrammingInterface.ActionTimer.OnUpdate(timePassed)
    if not VisualProgrammingInterface.ActionTimer.isWaiting then 
        --Debug.Print("Timer not waiting, skipping update")
        return 
    end
    
    -- Update timer and check for completion
    local oldTime = VisualProgrammingInterface.ActionTimer.currentTime
    local currentTime = oldTime + timePassed
    VisualProgrammingInterface.ActionTimer.currentTime = currentTime
    
    --Debug.Print(string.format("Timer tick: %.3f -> %.3f (target: %.3f)", 
    --    oldTime, currentTime, VisualProgrammingInterface.ActionTimer.targetTime))
    
    if currentTime >= VisualProgrammingInterface.ActionTimer.targetTime then
        Debug.Print("*** Timer reached target time ***")
        
        -- Store state before resetting
        local currentQueueId = VisualProgrammingInterface.ActionTimer.currentQueueId
        local hasQueue = #VisualProgrammingInterface.ActionTimer.functionQueue > 0
        local callback = VisualProgrammingInterface.ActionTimer.callback
        
        -- Keep isWaiting true until we process callback
        VisualProgrammingInterface.ActionTimer.currentTime = 0
        
        -- Execute stored callback
        if callback then
            Debug.Print("Executing timer callback for queue " .. tostring(currentQueueId))
            local success, isComplete = pcall(callback)
            
            if success then
                if isComplete then
                    Debug.Print("Callback indicated completion")
                    VisualProgrammingInterface.ActionTimer.isComplete = true
                else
                    Debug.Print("Callback indicated more steps needed")
                end
                
                -- Process next function in queue if not complete
                if not VisualProgrammingInterface.ActionTimer.isComplete and hasQueue then
                    Debug.Print("Executing next function in queue " .. tostring(currentQueueId))
                    local nextFunc = table.remove(VisualProgrammingInterface.ActionTimer.functionQueue, 1)
                    nextFunc()
                else
                    Debug.Print("Function queue complete for " .. tostring(currentQueueId))
                    -- Notify completion callbacks after entire sequence
                    VisualProgrammingInterface.ActionTimer:notifyCompletion()
                    -- Now reset everything
                    Debug.Print("Resetting timer state")
                    VisualProgrammingInterface.ActionTimer.isWaiting = false
                    VisualProgrammingInterface.ActionTimer.callback = nil
                    VisualProgrammingInterface.ActionTimer.currentQueueId = nil
                    VisualProgrammingInterface.ActionTimer.isComplete = false
                    VisualProgrammingInterface.ActionTimer.functionQueue = {}
                end
            else
                Debug.Print("Error in timer callback: " .. tostring(isComplete))
                -- Notify completion callbacks even on error
                VisualProgrammingInterface.ActionTimer:notifyCompletion()
                -- Reset state on error
                VisualProgrammingInterface.ActionTimer.isWaiting = false
                VisualProgrammingInterface.ActionTimer.callback = nil
                VisualProgrammingInterface.ActionTimer.currentQueueId = nil
                VisualProgrammingInterface.ActionTimer.isComplete = false
                VisualProgrammingInterface.ActionTimer.functionQueue = {}
            end
        end
    end
end

-- Helper function for waiting
local function WaitTimer(duration, callback, queueId)
    Debug.Print("WaitTimer called: " .. duration .. "ms, queue: " .. tostring(queueId))
    
    -- Always create a new timer function
    local timerFunc = function()
        -- Initialize timer state
        Debug.Print("Setting up new timer for " .. duration .. "ms")
        VisualProgrammingInterface.ActionTimer.currentTime = 0
        VisualProgrammingInterface.ActionTimer.targetTime = duration / 1000
        VisualProgrammingInterface.ActionTimer.isWaiting = true
        VisualProgrammingInterface.ActionTimer.callback = callback
        
        -- Update queue state
        if queueId then
            Debug.Print("Setting queue ID: " .. queueId)
            VisualProgrammingInterface.ActionTimer.currentQueueId = queueId
            if not VisualProgrammingInterface.ActionTimer.functionQueue then
                VisualProgrammingInterface.ActionTimer.functionQueue = {}
            end
        else
            Debug.Print("No queue ID provided")
            VisualProgrammingInterface.ActionTimer.functionQueue = {}
            VisualProgrammingInterface.ActionTimer.currentQueueId = nil
        end
        
        Debug.Print("Timer initialized - target: " .. VisualProgrammingInterface.ActionTimer.targetTime .. "s")
    end
    
    -- Handle timer execution
    if VisualProgrammingInterface.ActionTimer.isWaiting then
        Debug.Print("Timer already running, queueing function")
        if not VisualProgrammingInterface.ActionTimer.functionQueue then
            VisualProgrammingInterface.ActionTimer.functionQueue = {}
        end
        table.insert(VisualProgrammingInterface.ActionTimer.functionQueue, timerFunc)
    else
        Debug.Print("Starting timer immediately")
        timerFunc()
    end
    
    return true
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
                
                -- Add casting delay based on spell speed
                local castTime = SpellsInfo.GetSpellSpeed(spellId) * 1000
                local recoveryTime = SpellsInfo.GetRecoverySpeed() * 1000
                
                Debug.Print("Cast time: " .. castTime .. "ms, Recovery time: " .. recoveryTime .. "ms")
                        
                -- Create a unique ID for this spell cast sequence
                local queueId = "spell_" .. spellId .. "_" .. tostring(Interface.TimeSinceLogin)
                
                -- Start casting the spell FIRST
                Debug.Print("Starting spell cast")
                GameData.UseRequests.UseSpellcast = spellId
                GameData.UseRequests.UseTarget = 0
                Interface.SpellUseRequest()
                UserActionCastSpell(spellId)
        
                -- Step 1: Wait for cast time
                WaitTimer(castTime, function()
                    Debug.Print("Cast time complete, handling targeting")
                    
                    -- Handle targeting immediately after cast time
                    if params.target == "self" then
                        HandleSingleLeftClkTarget(WindowData.PlayerStatus.PlayerId)
                        Debug.Print("Self-targeting complete")
                    end
                    
                    -- Step 2: Wait for full recovery time before marking complete
                    WaitTimer(recoveryTime, function()
                        Debug.Print("Recovery time complete - full sequence done")
                        return true -- Only return true after FULL recovery
                    end, queueId)
                    
                    -- Continue to recovery timer
                    return false 
                end, queueId)
                
                return true
            end
            Debug.Print("Spell ID not found")
            return false
        end
})

    -- Magic Actions
    VisualProgrammingInterface.Actions:register({
        name = "Heal Self",
        description = L"Cast healing on yourself",
        category = Categories.MAGIC,
        icon = { texture = "icon856001", x = 5, y = 5 },
        params = {},
        execute = function()
            local spellId = 29 -- Heal spell ID
            
            -- Start casting the spell
            GameData.UseRequests.UseSpellcast = spellId
            GameData.UseRequests.UseTarget = 0
            Interface.SpellUseRequest()
            UserActionCastSpell(spellId)
            
            -- Add casting delay based on spell speed
            local castTime = SpellsInfo.GetSpellSpeed(spellId) * 1000
            local recoveryTime = SpellsInfo.GetRecoverySpeed() * 1000
            
            -- Create a unique ID for this heal sequence
            local queueId = "spell_" .. tostring(Interface.TimeSinceLogin)
            
            -- Step 1: Wait for cast time
            WaitTimer(castTime, function()
                Debug.Print("Cast time complete, targeting self")
                HandleSingleLeftClkTarget(WindowData.PlayerStatus.PlayerId)
                Debug.Print("Self-targeting complete")
                
                -- Start recovery timer immediately after targeting
                WaitTimer(recoveryTime, function()
                    Debug.Print("Recovery time complete")
                    return true
                end, queueId)
                
                -- Continue to recovery timer
                return false
            end, queueId)
            
            return true
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
                    return true
                end, queueId)
            end
            
            return true
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
            
            local queueId = "hide_" .. tostring(Interface.TimeSinceLogin)
            
            -- Step 1: Base skill delay
            WaitTimer(1000, function()
                Debug.Print("Hide base delay complete")
                if params.retry then
                    return false
                else
                    return true
                end
            end, queueId)
            
            -- Step 2: Optional retry delay
            if params.retry then
                WaitTimer(params.retryDelay, function()
                    Debug.Print("Hide retry delay complete")
                    return true
                end, queueId)
            end
            
            return true
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
            
            local queueId = "meditate_" .. tostring(Interface.TimeSinceLogin)
            
            -- Step 1: Base skill delay
            WaitTimer(1000, function()
                Debug.Print("Meditate base delay complete")
                return false
            end, queueId)
            
            -- Step 2: Meditation duration
            WaitTimer(params.duration, function()
                Debug.Print("Meditation duration complete")
                return true
            end, queueId)
            
            return true
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
                return true
            end, queueId)
            return true
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
        
        -- Set block name and description
        LabelSetText(blockName .. "Name", StringToWString(type))
        LabelSetText(blockName .. "Description", VisualProgrammingInterface.GetBlockDescription(type))
        
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
