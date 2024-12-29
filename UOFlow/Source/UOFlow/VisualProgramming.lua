-- Main entry point for Visual Programming Interface
VisualProgrammingInterface = {}

-- Handle test flow button click
function OnTestFlowClick()
    -- Forward to the interface handler
    if VisualProgrammingInterface and VisualProgrammingInterface.Execution then
        local success, results = VisualProgrammingInterface.Execution:testFlow()
        
        if success then
            if results.success then
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
                Debug.Print("Flow test failed: " .. (results.error or "Unknown error"))
            end
        else
            Debug.Print("Could not start flow test: " .. (results or "Unknown error"))
        end
    else
        Debug.Print("Error: Execution system not initialized")
    end
end

-- Store reference in interface table for internal use
VisualProgrammingInterface.OnTestFlowClick = OnTestFlowClick

-- Global initialization - forwards to core initialization
function Initialize()
    Debug.Print("Global initialization of Visual Programming Interface")
    VisualProgrammingInterface.Initialize()
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
