-- Initialize the visual programming interface
VisualProgrammingInterface = VisualProgrammingInterface or {}
VisualProgrammingInterface.Actions = VisualProgrammingInterface.Actions or {}
VisualProgrammingInterface.Actions.registry = VisualProgrammingInterface.Actions.registry or {}
VisualProgrammingInterface.Actions.defaultParams = VisualProgrammingInterface.Actions.defaultParams or {}
VisualProgrammingInterface.Actions.categories = VisualProgrammingInterface.Actions.categories or {
    GENERAL = "General",
    COMBAT = "Combat",
    MAGIC = "Magic",
    SKILLS = "Skills",
    ITEMS = "Items",
    MOVEMENT = "Movement",
    TARGETING = "Targeting"
}

local function VPUIRenderStarterBlock(block, index)
    if type(block) ~= "table" or block.id == nil then
        return false
    end

    local scrollChild = "VisualProgrammingInterfaceWindowScrollWindowScrollChild"
    if not DoesWindowNameExist(scrollChild) then
        return false
    end

    local blockName = "Block" .. tostring(block.id)
    if not DoesWindowNameExist(blockName) then
        CreateWindowFromTemplate(blockName, "BlockTemplate", scrollChild)
    end

    if not DoesWindowNameExist(blockName) then
        return false
    end

    WindowSetDimensions(blockName, 380, 50)
    WindowClearAnchors(blockName)
    WindowAddAnchor(blockName, "topleft", scrollChild, "topleft", 0, index * 80)
    WindowSetLayer(blockName, Window.Layers.DEFAULT)
    WindowSetShowing(blockName, true)
    WindowSetAlpha(blockName, 1.0)

    local description = type(block.getDescription) == "function" and block:getDescription() or tostring(block.type)
    if DoesWindowNameExist(blockName .. "Name") then
        LabelSetText(blockName .. "Name", StringToWString(description))
        WindowSetLayer(blockName .. "Name", Window.Layers.DEFAULT)
        WindowSetShowing(blockName .. "Name", true)
    end
    if DoesWindowNameExist(blockName .. "Description") then
        LabelSetText(blockName .. "Description", StringToWString(description))
        WindowSetLayer(blockName .. "Description", Window.Layers.DEFAULT)
        WindowSetShowing(blockName .. "Description", true)
    end
    if DoesWindowNameExist(blockName .. "Icon") then
        ButtonSetTexture(blockName .. "Icon", InterfaceCore.ButtonStates.STATE_NORMAL, "icon000623", 5, 5)
        ButtonSetTexture(blockName .. "Icon", InterfaceCore.ButtonStates.STATE_NORMAL_HIGHLITE, "icon000623", 5, 5)
        ButtonSetTexture(blockName .. "Icon", InterfaceCore.ButtonStates.STATE_PRESSED, "icon000623", 5, 5)
        ButtonSetTexture(blockName .. "Icon", InterfaceCore.ButtonStates.STATE_PRESSED_HIGHLITE, "icon000623", 5, 5)
    end

    local width, height = WindowGetDimensions(scrollChild)
    local newHeight = math.max(height or 0, (index + 1) * 80)
    WindowSetDimensions(scrollChild, width or 840, newHeight)

    return true
end

local function VPUICreateStarterBlock(manager, blockType, index)
    if type(manager) ~= "table" then
        return nil
    end

    local params = {}
    if type(VisualProgrammingInterface.CloneDefaultParams) == "function" then
        params = VisualProgrammingInterface.CloneDefaultParams(blockType)
    elseif type(VisualProgrammingInterface.Actions) == "table"
        and type(VisualProgrammingInterface.Actions.getDefaultParams) == "function" then
        local source = VisualProgrammingInterface.Actions:getDefaultParams(blockType)
        if type(source) == "table" then
            for key, value in pairs(source) do
                params[key] = value
            end
        end
    end

    local id = tonumber(manager.nextBlockId) or 1
    local block = {
        id = id,
        type = blockType,
        x = 0,
        y = index * 80,
        column = "middle",
        isDragging = false,
        params = params,
        state = "pending",
        connections = {},
        windowName = "Block" .. tostring(id),
        instanceName = blockType .. " #" .. tostring(id)
    }

    if type(VisualProgrammingInterface.Block) == "table" then
        setmetatable(block, VisualProgrammingInterface.Block)
    end

    manager.blocks[id] = block
    manager.nextBlockId = id + 1
    return block
end

local VPUI_STARTER_BLOCKS = {
    { type = "Walk Step", index = 0, direction = "North" },
    { type = "Walk Step", index = 1, direction = "NorthEast" },
    { type = "Walk Step", index = 2, direction = "East" },
    { type = "Walk Step", index = 3, direction = "SouthEast" },
    { type = "Walk Step", index = 4, direction = "South" },
    { type = "Walk Step", index = 5, direction = "SouthWest" },
    { type = "Walk Step", index = 6, direction = "West" },
    { type = "Walk Step", index = 7, direction = "NorthWest" },
}

local function VPUIGetManagerBlockCount()
    local count = 0
    local manager = VisualProgrammingInterface.manager
    if manager and type(manager.blocks) == "table" then
        for _, block in pairs(manager.blocks) do
            if type(block) == "table" then
                count = count + 1
            end
        end
    end
    return count
end

VisualProgrammingInterface.GetManagerBlockCount = VPUIGetManagerBlockCount

function VisualProgrammingInterface.EnsureStarterBlocks(reason)
    local manager = VisualProgrammingInterface.manager
    if type(manager) ~= "table" or type(manager.blocks) ~= "table" then
        VisualProgrammingInterface._starterSeedRequested = true
        if type(UOWNativeLog) == "function" then
            UOWNativeLog("[VPUI] ensure starter blocks deferred",
                "reason=" .. tostring(reason),
                "manager=" .. tostring(type(manager)),
                "blocks=" .. tostring(manager and type(manager.blocks) or "nil"))
        end
        return false
    end

    local scrollChild = "VisualProgrammingInterfaceWindowScrollWindowScrollChild"
    if not DoesWindowNameExist(scrollChild) then
        VisualProgrammingInterface._starterSeedRequested = true
        if type(UOWNativeLog) == "function" then
            UOWNativeLog("[VPUI] ensure starter blocks deferred",
                "reason=" .. tostring(reason),
                "missing=" .. tostring(scrollChild))
        end
        return false
    end

    local existing = VPUIGetManagerBlockCount()
    if type(UOWNativeLog) == "function" then
        UOWNativeLog("[VPUI] ensure starter blocks", "reason=" .. tostring(reason), "existing=" .. tostring(existing))
    end
    if existing > 0 then
        VisualProgrammingInterface._starterBlocksSeeded = true
        VisualProgrammingInterface._starterSeedRequested = false
        return true
    end

    local createdBlocks = {}
    local previousBlock = nil
    for _, blockInfo in ipairs(VPUI_STARTER_BLOCKS) do
        if type(UOWNativeLog) == "function" then
            UOWNativeLog("[VPUI] starter block request",
                tostring(blockInfo.index),
                tostring(blockInfo.type),
                "direction=" .. tostring(blockInfo.direction),
                "reason=" .. tostring(reason))
        end
        local block = VPUICreateStarterBlock(manager, blockInfo.type, blockInfo.index)
        if block then
            block.params = block.params or {}
            block.params.direction = blockInfo.direction
            local rendered = VPUIRenderStarterBlock(block, blockInfo.index)
            if previousBlock then
                previousBlock.connections = previousBlock.connections or {}
                table.insert(previousBlock.connections, { id = block.id })
            end
            previousBlock = block
            table.insert(createdBlocks, block)
            if type(UOWNativeLog) == "function" then
                UOWNativeLog("[VPUI] starter block created",
                    tostring(block.id),
                    tostring(block.type),
                    "direction=" .. tostring(block.params.direction),
                    "rendered=" .. tostring(rendered),
                    "reason=" .. tostring(reason))
            end
        else
            if type(UOWNativeLog) == "function" then
                UOWNativeLog("[VPUI] starter block failed", tostring(blockInfo.index), tostring(blockInfo.type), "reason=" .. tostring(reason))
            end
            break
        end
    end

    local scrollWindow = "VisualProgrammingInterfaceWindowScrollWindow"
    if DoesWindowNameExist(scrollWindow) then
        ScrollWindowUpdateScrollRect(scrollWindow)
    end

    if type(UOWNativeLog) == "function" then
        UOWNativeLog("[VPUI] starter blocks ready",
            "created=" .. tostring(#createdBlocks),
            "manager=" .. tostring(VPUIGetManagerBlockCount()),
            "reason=" .. tostring(reason))
    end

    if #createdBlocks > 0 and VPUIGetManagerBlockCount() > 0 then
        VisualProgrammingInterface._starterBlocksSeeded = true
        VisualProgrammingInterface._starterSeedRequested = false
        return true
    end

    VisualProgrammingInterface._starterSeedRequested = true
    return false
end

function VisualProgrammingInterface.Initialize()
    Debug.Print("Initializing Visual Programming Interface")
    
    local windowName = "VisualProgrammingInterfaceWindow"
    VisualProgrammingInterface.manager = VisualProgrammingInterface.Manager:new()
    
    -- Ensure main window exists
    if not DoesWindowNameExist(windowName) then
        Debug.Print("Main window does not exist")
        return
    end
    ButtonSetText("VisualProgrammingInterfaceWindowTestButton", L"Test")
    
    -- Set window text
    LabelSetText(windowName .. "Chrome_UO_TitleBar_WindowTitle", L"Visual Programming Interface")
    
    -- Initialize scroll window and scroll child
    local scrollWindow = windowName .. "ScrollWindow"
    local scrollChild = scrollWindow .. "ScrollChild"
    
    if not DoesWindowNameExist(scrollWindow) or not DoesWindowNameExist(scrollChild) then
        Debug.Print("Warning: Scroll windows not found during initialization")
        return
    end
    
    -- Set up scroll windows with UO pattern
    WindowSetDimensions(scrollChild, 840, 0)
    WindowSetLayer(scrollChild, Window.Layers.DEFAULT)
    WindowSetShowing(scrollChild, true)
    ScrollWindowUpdateScrollRect(scrollWindow)
    
    -- Set up right scroll window
    local rightScrollWindow = windowName .. "ScrollWindowRight"
    local rightScrollChild = rightScrollWindow .. "ScrollChildRight"
    if DoesWindowNameExist(rightScrollWindow) and DoesWindowNameExist(rightScrollChild) then
        WindowSetDimensions(rightScrollChild, 300, 0)
        WindowSetLayer(rightScrollChild, Window.Layers.DEFAULT)
        WindowSetShowing(rightScrollChild, true)
        ScrollWindowUpdateScrollRect(rightScrollWindow)
    end
    
    -- Initialize Actions system
    if VisualProgrammingInterface.Actions.initialize then
        VisualProgrammingInterface.Actions:initialize()
    end
    
    -- Initialize block types
    if VisualProgrammingInterface.InitializeBlockTypes then
        VisualProgrammingInterface.InitializeBlockTypes()
    end
    
    if type(UOWNativeLog) == "function" then
        UOWNativeLog("[VPUI] starter block seed deferred", "reason=initialize")
    end

    if type(VisualProgrammingInterface.RegisterUpdateHandlers) == "function" then
        VisualProgrammingInterface.RegisterUpdateHandlers("initialize")
    end

    if WindowGetShowing(windowName) and type(VisualProgrammingInterface.EnsureStarterBlocks) == "function" then
        local seeded = VisualProgrammingInterface.EnsureStarterBlocks("initialize_visible")
        if type(UOWNativeLog) == "function" then
            UOWNativeLog("[VPUI] initialize visible seed",
                "seeded=" .. tostring(seeded),
                "existing=" .. tostring(VPUIGetManagerBlockCount()))
        end
    end
    
    -- Set proper window layers
    if DoesWindowNameExist("ActionEditBackground") then
        WindowSetLayer("ActionEditBackground", Window.Layers.BACKGROUND)
    end
    if DoesWindowNameExist("VisualProgrammingInterfaceWindowScrollWindow") then
        WindowSetLayer("VisualProgrammingInterfaceWindowScrollWindow", Window.Layers.DEFAULT)
    end
    
    Debug.Print("Visual Programming Interface initialized")
end

-- Function to create and display a block
function VisualProgrammingInterface.CreateBlock(blockType, index)
    -- Verify action exists
    local action = VisualProgrammingInterface.Actions:get(blockType)
    if not action then
        Debug.Print("Error: Unknown action type: " .. blockType)
        return nil
    end
    Debug.Print("Creating block of type: " .. blockType .. " at index: " .. index)
    
    -- Get scroll child window name
    local scrollChild = "VisualProgrammingInterfaceWindowScrollWindowScrollChild"
    if not DoesWindowNameExist(scrollChild) then
        Debug.Print("Scroll child window does not exist")
        return nil
    end
    
    -- Create block in manager
    local block = VisualProgrammingInterface.manager:createBlock(blockType, 0, index * 80)
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
        
        -- Set block name (include instance identifier) and description
        LabelSetText(blockName .. "Name", StringToWString(block.instanceName or blockType))
        LabelSetText(blockName .. "Description", StringToWString(block:getDescription()))
        
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
        
        Debug.Print("Block created successfully")
    else
        Debug.Print("Block window already exists: " .. blockName)
    end
    
    -- Set block icon using helper function (do this for both new and existing windows)
    local iconWindow = blockName .. "Icon"
    Debug.Print("Setting icon for window: " .. iconWindow)

    local iconInfo = nil
    if type(VisualProgrammingInterface.GetBlockIcon) == "function" then
        iconInfo = VisualProgrammingInterface.GetBlockIcon(blockType)
    elseif type(VisualProgrammingInterface.NormalizeBlockIcon) == "function" then
        local action = VisualProgrammingInterface.Actions:get(blockType)
        iconInfo = VisualProgrammingInterface.NormalizeBlockIcon(action and action.icon)
    end

    iconInfo = iconInfo or { texture = "icon000623", x = 5, y = 5 }
    Debug.Print("Resolved icon for " .. iconWindow .. ": " .. tostring(iconInfo.texture))
    ButtonSetTexture(iconWindow, InterfaceCore.ButtonStates.STATE_NORMAL, iconInfo.texture, iconInfo.x, iconInfo.y)
    ButtonSetTexture(iconWindow, InterfaceCore.ButtonStates.STATE_NORMAL_HIGHLITE, iconInfo.texture, iconInfo.x, iconInfo.y)
    ButtonSetTexture(iconWindow, InterfaceCore.ButtonStates.STATE_PRESSED, iconInfo.texture, iconInfo.x, iconInfo.y)
    ButtonSetTexture(iconWindow, InterfaceCore.ButtonStates.STATE_PRESSED_HIGHLITE, iconInfo.texture, iconInfo.x, iconInfo.y)
    
    return block
end

-- Show the visual programming interface window
function VisualProgrammingInterface.ShowWindow()
    if not DoesWindowNameExist("VisualProgrammingInterfaceWindow") then
        CreateWindowFromTemplate("VisualProgrammingInterfaceWindow", "UO_DefaultWindow", "Root")
    end
    -- Use the execution-aware Show function that handles update registration
    VisualProgrammingInterface.Show()
end

-- Hide the visual programming interface window
function VisualProgrammingInterface.HideWindow()
    if DoesWindowNameExist("VisualProgrammingInterfaceWindow") then
        -- Clean up any existing property editors
        local rightScrollChild = "VisualProgrammingInterfaceWindowScrollWindowRightScrollChildRight"
        if DoesWindowNameExist(rightScrollChild) then
            DestroyWindow(rightScrollChild)
            CreateWindowFromTemplate(rightScrollChild, "ScrollChild", "VisualProgrammingInterfaceWindowScrollWindowRight")
        end
        
        -- Use the execution-aware Hide function that handles update unregistration
        VisualProgrammingInterface.Hide()
    end
end

-- Toggle the visual programming interface window
function VisualProgrammingInterface.Toggle()
    if DoesWindowNameExist("VisualProgrammingInterfaceWindow") and WindowGetShowing("VisualProgrammingInterfaceWindow") then
        VisualProgrammingInterface.HideWindow()
    else
        VisualProgrammingInterface.ShowWindow()
    end
end
