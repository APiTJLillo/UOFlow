-- Main entry point for Visual Programming Interface
VisualProgrammingInterface = {}

-- Initialize the Visual Programming Interface

-- Global initialization
function Initialize()
    Debug.Print("Global initialization of Visual Programming Interface")
    VisualProgrammingInterface.Initialize()
end

-- Initialize all subsystems
function VisualProgrammingInterface.Initialize()
    Debug.Print("Initializing Visual Programming Interface")
    
    -- Check and initialize Actions system
    if not VisualProgrammingInterface.Actions then
        Debug.Print("Error: Actions system not found")
        return false
    end
    
    if type(VisualProgrammingInterface.Actions.initialize) ~= "function" then
        Debug.Print("Error: Actions system initialize method not found")
        return false
    end
    
    local success, err = pcall(function()
        VisualProgrammingInterface.Actions:initialize()
    end)
    
    if not success then
        Debug.Print("Error initializing Actions system: " .. tostring(err))
        return false
    end
    
    -- Initialize manager last
    if VisualProgrammingInterface.manager then
        if type(VisualProgrammingInterface.manager.initialize) == "function" then
            success, err = pcall(function()
                VisualProgrammingInterface.manager:initialize()
            end)
            
            if not success then
                Debug.Print("Error initializing manager: " .. tostring(err))
                return false
            end
        else
            Debug.Print("Warning: Manager initialize method not found")
        end
    end
    
    -- Set window title
    if DoesWindowNameExist("VisualProgrammingInterfaceWindow_UO_TitleBar_WindowTitle") then
        LabelSetText("VisualProgrammingInterfaceWindow_UO_TitleBar_WindowTitle", StringToWString("Visual Programming Interface"))
    end
    
    -- Register for updates
    if WindowGetShowing("VisualProgrammingInterfaceWindow") then
        RegisterEventHandler("OnUpdate", "VisualProgrammingInterface.Execution.OnUpdate")
    end
    
    Debug.Print("Visual Programming Interface initialized successfully")
    return true
end

-- Show interface
function VisualProgrammingInterface.Show()
    WindowSetShowing("VisualProgrammingInterfaceWindow", true)
    RegisterEventHandler("OnUpdate", "VisualProgrammingInterface.Execution.OnUpdate")
end


-- Hide interface
function VisualProgrammingInterface.Hide()
    WindowSetShowing("VisualProgrammingInterfaceWindow", false)
    UnregisterEventHandler("OnUpdate", "VisualProgrammingInterface.Execution.OnUpdate")
end
