-- Initialize the visual programming interface
VisualProgrammingInterface = {
    Actions = {
        registry = {},
        defaultParams = {},
        categories = {
            GENERAL = "General",
            COMBAT = "Combat",
            MAGIC = "Magic",
            SKILLS = "Skills",
            ITEMS = "Items",
            MOVEMENT = "Movement",
            TARGETING = "Targeting"
        }
    }
}

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
    
    -- Initialize with starter blocks
    Debug.Print("Creating starter blocks")
    local blocks = {
        { type = "Cast Spell", index = 0 },
        { type = "Cast Spell", index = 1 },
    }
    
    -- Create blocks and establish connections
    local createdBlocks = {}
    local previousBlock = nil
    for _, blockInfo in ipairs(blocks) do
        local block = VisualProgrammingInterface.CreateBlock(blockInfo.type, blockInfo.index)
        if block then
            Debug.Print("Created block: " .. blockInfo.type .. " at index " .. blockInfo.index)
            local blockName = "Block" .. block.id
            if DoesWindowNameExist(blockName) then
                WindowSetLayer(blockName, Window.Layers.DEFAULT)
                WindowSetShowing(blockName, true)
            end
            
            -- Connect to previous block if it exists
            if previousBlock then
                Debug.Print("Connecting block " .. previousBlock.id .. " to block " .. block.id)
                if not previousBlock.connections then
                    previousBlock.connections = {}
                end
                table.insert(previousBlock.connections, {id = block.id})
            end
            
            table.insert(createdBlocks, block)
            previousBlock = block
        else
            Debug.Print("Failed to create block: " .. blockInfo.type)
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
        LabelSetText(blockName .. "Description", block:getDescription())
        
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
    
    -- Get action definition for icon
    local action = VisualProgrammingInterface.Actions:get(blockType)
    if action and action.icon then
        Debug.Print("Found icon for action: " .. action.icon.texture)
        ButtonSetTexture(iconWindow, InterfaceCore.ButtonStates.STATE_NORMAL, action.icon.texture, action.icon.x, action.icon.y)
        ButtonSetTexture(iconWindow, InterfaceCore.ButtonStates.STATE_NORMAL_HIGHLITE, action.icon.texture, action.icon.x, action.icon.y)
        ButtonSetTexture(iconWindow, InterfaceCore.ButtonStates.STATE_PRESSED, action.icon.texture, action.icon.x, action.icon.y)
        ButtonSetTexture(iconWindow, InterfaceCore.ButtonStates.STATE_PRESSED_HIGHLITE, action.icon.texture, action.icon.x, action.icon.y)
    else
        Debug.Print("Using default icon for block")
        -- Use a default icon if none specified
        ButtonSetTexture(iconWindow, InterfaceCore.ButtonStates.STATE_NORMAL, "icon000623", 5, 5)
        ButtonSetTexture(iconWindow, InterfaceCore.ButtonStates.STATE_NORMAL_HIGHLITE, "icon000623", 5, 5)
        ButtonSetTexture(iconWindow, InterfaceCore.ButtonStates.STATE_PRESSED, "icon000623", 5, 5)
        ButtonSetTexture(iconWindow, InterfaceCore.ButtonStates.STATE_PRESSED_HIGHLITE, "icon000623", 5, 5)
    end
    
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
