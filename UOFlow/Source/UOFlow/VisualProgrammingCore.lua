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
    
    -- Set window text
    LabelSetText(windowName .. "Title", L"Visual Programming Interface")
    --ButtonSetText(windowName .. "OKButton", L"OK")
    ButtonSetText(windowName .. "AddBlockButton", L"Add Block")
    
    -- Initialize scroll window and scroll child
    local scrollWindow = windowName .. "ScrollWindow"
    local scrollChild = scrollWindow .. "ScrollChild"
    
    if not DoesWindowNameExist(scrollWindow) or not DoesWindowNameExist(scrollChild) then
        Debug.Print("Warning: Scroll windows not found during initialization")
        return
    end
    
    -- Set up scroll window with UO pattern
    WindowSetDimensions(scrollChild, 840, 0)
    WindowSetLayer(scrollChild, Window.Layers.DEFAULT)
    WindowSetShowing(scrollChild, true)
    ScrollWindowUpdateScrollRect(scrollWindow)
    
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
        { type = "Target Self", index = 0 },
        { type = "Cast Spell", index = 1 },
        { type = "Wait", index = 2 },
        { type = "Heal Self", index = 3 }
    }
    
    -- Create blocks
    local createdBlocks = {}
    for _, blockInfo in ipairs(blocks) do
        local block = VisualProgrammingInterface.CreateBlock(blockInfo.type, blockInfo.index)
        if block then
            Debug.Print("Created block: " .. blockInfo.type .. " at index " .. blockInfo.index)
            local blockName = "Block" .. block.id
            if DoesWindowNameExist(blockName) then
                WindowSetLayer(blockName, Window.Layers.DEFAULT)
                WindowSetShowing(blockName, true)
            end
            table.insert(createdBlocks, block)
        else
            Debug.Print("Failed to create block: " .. blockInfo.type)
        end
    end
    
    -- Create initial connections between blocks
    for i = 1, #createdBlocks - 1 do
        VisualProgrammingInterface.manager:connectBlocks(createdBlocks[i].id, createdBlocks[i + 1].id)
    end
    
    -- Draw initial connections
    VisualProgrammingInterface.UpdateConnections()
    
    -- Set proper window layers
    if DoesWindowNameExist("ActionEditBackground") then
        WindowSetLayer("ActionEditBackground", Window.Layers.BACKGROUND)
    end
    if DoesWindowNameExist("VisualProgrammingInterfaceWindowScrollWindow") then
        WindowSetLayer("VisualProgrammingInterfaceWindowScrollWindow", Window.Layers.DEFAULT)
    end
    
    Debug.Print("Visual Programming Interface initialized")
end

-- Show the visual programming interface window
function VisualProgrammingInterface.Show()
    if not DoesWindowNameExist("VisualProgrammingInterfaceWindow") then
        CreateWindowFromTemplate("VisualProgrammingInterfaceWindow", "UO_DefaultWindow", "Root")
    end
    WindowSetShowing("VisualProgrammingInterfaceWindow", true)
end

-- Hide the visual programming interface window
function VisualProgrammingInterface.Hide()
    if DoesWindowNameExist("VisualProgrammingInterfaceWindow") then
        WindowSetShowing("VisualProgrammingInterfaceWindow", false)
    end
end

-- Toggle the visual programming interface window
function VisualProgrammingInterface.Toggle()
    if DoesWindowNameExist("VisualProgrammingInterfaceWindow") and WindowGetShowing("VisualProgrammingInterfaceWindow") then
        VisualProgrammingInterface.Hide()
    else
        VisualProgrammingInterface.Show()
    end
end