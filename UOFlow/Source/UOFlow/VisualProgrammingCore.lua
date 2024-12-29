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
