-- Block type definitions and utilities

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
            CreateParameter("spellId", "number", 1),
            CreateParameter("target", "select", "self", {"self", "target", "last"})
        },
        validate = function(params)
            local spellId = tonumber(params.spellId)
            return spellId and spellId > 0 and spellId < 100
        end,
        execute = function(params)
            GameData.UseRequests.UseSpellcast = params.spellId
            GameData.UseRequests.UseTarget = 0
            Interface.SpellUseRequest()
            UserActionCastSpell(params.spellId)
            return true
        end
    })

    -- Item Actions
    VisualProgrammingInterface.Actions:register({
        name = "Use Item",
        description = L"Use a selected item",
        category = Categories.ITEMS,
        icon = { texture = "icon000646", x = 5, y = 5 },
        params = {
            CreateParameter("itemId", "number", 1)
        },
        execute = function(params)
            UserActionUseItem()
            return true
        end
    })

    -- Targeting Actions
    VisualProgrammingInterface.Actions:register({
        name = "Target Self",
        description = L"Target yourself",
        category = Categories.TARGETING,
        icon = { texture = "icon000645", x = 5, y = 5 },
        params = {},
        execute = function()
            UserActionTargetSelf()
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
            Interface.WaitTimer(params.time)
            return true
        end
    })

    -- Movement Actions
    VisualProgrammingInterface.Actions:register({
        name = "Move",
        description = L"Move in a direction",
        category = Categories.MOVEMENT,
        icon = { texture = "icon000667", x = 5, y = 5 },
        params = {
            CreateParameter("direction", "select", "north", {"north", "south", "east", "west"})
        },
        execute = function(params)
            -- TODO: Implement movement logic
            return true
        end
    })

    -- Combat Actions
    VisualProgrammingInterface.Actions:register({
        name = "Attack",
        description = L"Attack nearest target",
        category = Categories.COMBAT,
        icon = { texture = "icon000773", x = 5, y = 5 },
        params = {},
        execute = function()
            -- TODO: Implement attack logic
            return true
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
            GameData.UseRequests.UseSpellcast = 29
            GameData.UseRequests.UseTarget = 0
            Interface.SpellUseRequest()
            UserActionCastSpell(29)
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
                Interface.WaitTimer(10000) -- Wait for bandage to complete
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
            if params.retry then
                Interface.WaitTimer(params.retryDelay)
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
            Interface.WaitTimer(params.duration)
            return true
        end
    })

    -- Targeting Actions
    VisualProgrammingInterface.Actions:register({
        name = "Target Nearest",
        description = L"Target the nearest mobile",
        category = Categories.TARGETING,
        icon = { texture = "icon000773", x = 5, y = 5 },
        params = {
            CreateParameter("type", "select", "enemy", {"enemy", "friend", "any"}),
            CreateParameter("range", "number", 10)
        },
        execute = function(params)
            -- TODO: Implement target nearest logic
            return true
        end
    })

    -- Items Actions
    VisualProgrammingInterface.Actions:register({
        name = "Equip Item",
        description = L"Equip an item from backpack",
        category = Categories.ITEMS,
        icon = { texture = "icon000646", x = 5, y = 5 },
        params = {
            CreateParameter("slot", "select", "weapon", {
                "weapon", "shield", "helm", "neck", "chest", "arms",
                "gloves", "ring", "legs", "boots"
            })
        },
        execute = function(params)
            UserActionEquipItem()
            return true
        end
    })

    -- Combat Actions
    VisualProgrammingInterface.Actions:register({
        name = "Special Move",
        description = L"Execute a special combat move",
        category = Categories.COMBAT,
        icon = { texture = "icon000773", x = 5, y = 5 },
        params = {
            CreateParameter("move", "select", "primary", {"primary", "secondary"}),
            CreateParameter("wait", "boolean", true)
        },
        execute = function(params)
            -- TODO: Implement special move logic
            if params.wait then
                Interface.WaitTimer(1000)
            end
            return true
        end
    })

    -- Items Actions
    VisualProgrammingInterface.Actions:register({
        name = "Move Items",
        description = L"Move items between containers",
        category = Categories.ITEMS,
        icon = { texture = "icon000646", x = 5, y = 5 },
        params = {
            CreateParameter("type", "string", "all"),
            CreateParameter("quantity", "number", 0),
            CreateParameter("source", "select", "ground", {"ground", "backpack", "bank"}),
            CreateParameter("destination", "select", "backpack", {"backpack", "bank"})
        },
        execute = function(params)
            -- TODO: Implement move items logic
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
        WindowSetDimensions(blockName, 840, 50)
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

-- Add function to update all connections
function VisualProgrammingInterface.UpdateConnections()
    if VisualProgrammingInterface.manager then
        for _, block in pairs(VisualProgrammingInterface.manager.blocks) do
            block:drawConnections()
        end
    end
end
