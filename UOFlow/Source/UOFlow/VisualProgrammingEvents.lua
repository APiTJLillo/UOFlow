-- Event Handlers for Visual Programming Interface

function VisualProgrammingInterface.OnBlockRButtonUp()
    local blockName = SystemData.ActiveWindow.name:gsub("Icon$", "")
    local blockId = tonumber(blockName:match("Block(%d+)"))
    
    if not blockId then return end
    
    local block = VisualProgrammingInterface.manager:getBlock(blockId)
    if not block then return end
    
    local contextMenuOptions = {
        { str = L"Configure...", flags = 0, returnCode = "configure", param = blockId },
        { str = L"Move Up", flags = 0, returnCode = "move_up", param = blockId },
        { str = L"Move Down", flags = 0, returnCode = "move_down", param = blockId },
        { str = L"Delete", flags = 0, returnCode = "delete", param = blockName }
    }
    
    for _, option in ipairs(contextMenuOptions) do
        ContextMenu.CreateLuaContextMenuItemWithString(option.str, option.flags, option.returnCode, option.param)
    end
    ContextMenu.ActivateLuaContextMenu(VisualProgrammingInterface.ContextMenuCallback)
end

function VisualProgrammingInterface.OnBlockDragStart()
    local blockName = SystemData.ActiveWindow.name:gsub("Icon$", "")
    local block = VisualProgrammingInterface.manager:getBlock(tonumber(blockName:match("%d+")))
    if block then
        block:startDrag()
        VisualProgrammingInterface.dragStartX, VisualProgrammingInterface.dragStartY = WindowGetScreenPosition(blockName)
    end
end

function VisualProgrammingInterface.OnBlockDrag()
    local blockName = SystemData.ActiveWindow.name
    local block = VisualProgrammingInterface.manager:getBlock(tonumber(blockName:match("Block(%d+)")))
    
    if block and block.isDragging then
        local mouseX = SystemData.MousePosition.x
        local mouseY = SystemData.MousePosition.y
        
        local newY = mouseY - VisualProgrammingInterface.dragStartY
        
        WindowClearAnchors(blockName)
        WindowAddAnchor(blockName, "topleft", "VisualProgrammingInterfaceWindowScrollWindowScrollChild", "topleft", 0, newY)
        
        block.y = newY
        
    end
end

function VisualProgrammingInterface.OnBlockDragEnd()
    local blockName = SystemData.ActiveWindow.name
    local block = VisualProgrammingInterface.manager:getBlock(tonumber(blockName:match("Block(%d+)")))
    
    if block then
        block:stopDrag()
        
        local sortedBlocks = {}
        for _, b in pairs(VisualProgrammingInterface.manager.blocks) do
            table.insert(sortedBlocks, b)
        end
        table.sort(sortedBlocks, function(a, b) return a.y < b.y end)
        
        for index, b in ipairs(sortedBlocks) do
            local newY = (index - 1) * 80
            b.y = newY
            
            local bName = "Block" .. b.id
            if DoesWindowNameExist(bName) then
                WindowClearAnchors(bName)
                WindowAddAnchor(bName, "topleft", "VisualProgrammingInterfaceWindowScrollWindowScrollChild", "topleft", 0, newY)
            end
        end
        
    end
end

function VisualProgrammingInterface.ContextMenuCallback(returnCode, param)
    if returnCode == "configure" then
        local blockId = tonumber(param)
        local block = VisualProgrammingInterface.manager:getBlock(blockId)
        if block then
            Debug.Print("Configuring block: " .. tostring(block.type))
            if VisualProgrammingInterface and VisualProgrammingInterface.Config then
                Debug.Print("Config system found, showing window")
                VisualProgrammingInterface.Config:Show(block)
            else
                Debug.Print("Unable to configure block - Config system not available")
                Debug.Print("VisualProgrammingInterface: " .. tostring(VisualProgrammingInterface))
                if VisualProgrammingInterface then
                    Debug.Print("Config: " .. tostring(VisualProgrammingInterface.Config))
                end
            end
        end
    elseif returnCode == "delete" then
        local blockId = tonumber(param:match("Block(%d+)"))
        if blockId then
            VisualProgrammingInterface.manager:removeBlock(blockId)
            DestroyWindow(param)
        end
    elseif returnCode == "add_block" then
        local sortedBlocks = {}
        for _, block in pairs(VisualProgrammingInterface.manager.blocks) do
            table.insert(sortedBlocks, block)
        end
        table.sort(sortedBlocks, function(a, b) return a.y < b.y end)
        
        local newIndex = #sortedBlocks
        Debug.Print("Adding new block of type: " .. tostring(param))
        Debug.Print("Current block count: " .. tostring(newIndex))
        
        local block = VisualProgrammingInterface.CreateBlock(param, newIndex)
        if block then
            Debug.Print("Successfully created block with ID: " .. tostring(block.id))
            ScrollWindowUpdateScrollRect("VisualProgrammingInterfaceWindowScrollWindow")
        end
    elseif returnCode == "move_up" or returnCode == "move_down" then
        local blockId = tonumber(param)
        local block = VisualProgrammingInterface.manager:getBlock(blockId)
        if not block then return end
        
        local sortedBlocks = {}
        for _, b in pairs(VisualProgrammingInterface.manager.blocks) do
            table.insert(sortedBlocks, b)
        end
        table.sort(sortedBlocks, function(a, b) return a.y < b.y end)
        
        local currentIndex = 1
        for i, b in ipairs(sortedBlocks) do
            if b.id == blockId then
                currentIndex = i
                break
            end
        end
        
        local newIndex = currentIndex
        if returnCode == "move_up" and currentIndex > 1 then
            newIndex = currentIndex - 1
        elseif returnCode == "move_down" and currentIndex < #sortedBlocks then
            newIndex = currentIndex + 1
        end
        
        if newIndex ~= currentIndex then
            local temp = sortedBlocks[currentIndex]
            sortedBlocks[currentIndex] = sortedBlocks[newIndex]
            sortedBlocks[newIndex] = temp
            
            for index, b in ipairs(sortedBlocks) do
                local newY = (index - 1) * 80
                b.y = newY
                
                local bName = "Block" .. b.id
                if DoesWindowNameExist(bName) then
                    WindowClearAnchors(bName)
                    WindowAddAnchor(bName, "topleft", "VisualProgrammingInterfaceWindowScrollWindowScrollChild", "topleft", 0, newY)
                end
            end
            
        end
    end
end

-- Config Window Event Handlers
function VisualProgrammingInterface.ConfigOKButton()
    if VisualProgrammingInterface.Config then
        VisualProgrammingInterface.Config:Save()
    end
end

function VisualProgrammingInterface.ConfigCancelButton()
    if VisualProgrammingInterface.Config then
        VisualProgrammingInterface.Config:Cancel()
    end
end

function VisualProgrammingInterface.OKButton()
    local config = VisualProgrammingInterface.manager:saveConfiguration()
    Debug.Print("Configuration saved: " .. tostring(config))
end

-- Execution Control Event Handlers
function VisualProgrammingInterface.PlayButton()
    local status = VisualProgrammingInterface.Execution:getStatus()
    if status.isPaused then
        VisualProgrammingInterface.Execution:resume()
        ButtonSetText("VisualProgrammingInterfaceWindowPlayButton", L"Pause")
    elseif not status.isRunning then
        VisualProgrammingInterface.Execution:start()
        ButtonSetText("VisualProgrammingInterfaceWindowPlayButton", L"Pause")
    end
end

function VisualProgrammingInterface.PauseButton()
    local status = VisualProgrammingInterface.Execution:getStatus()
    if status.isRunning and not status.isPaused then
        VisualProgrammingInterface.Execution:pause()
        ButtonSetText("VisualProgrammingInterfaceWindowPlayButton", L"Resume")
    end
end

function VisualProgrammingInterface.StopButton()
    VisualProgrammingInterface.Execution:stop()
    ButtonSetText("VisualProgrammingInterfaceWindowPlayButton", L"Play")
end

function VisualProgrammingInterface.AddBlock()
    -- Get active categories
    local categories = VisualProgrammingInterface.Actions:getActiveCategories()
    local yOffset = 0
    
    -- Create category headers and action items
    for _, category in ipairs(categories) do
        -- Create category header
        local headerName = "Category_" .. category
        CreateWindowFromTemplate(headerName, "CategoryHeaderTemplate", "VisualProgrammingInterfaceWindowScrollWindowLeftScrollChildLeft")
        WindowClearAnchors(headerName)
        WindowAddAnchor(headerName, "topleft", "VisualProgrammingInterfaceWindowScrollWindowLeftScrollChildLeft", "topleft", 0, yOffset)
        LabelSetText(headerName .. "Text", StringToWString(category))
        yOffset = yOffset + 30
        
        -- Add actions in this category
        local categoryActions = VisualProgrammingInterface.Actions:getByCategory(category)
        local sortedActions = {}
        for name, action in pairs(categoryActions) do
            table.insert(sortedActions, {name = name, action = action})
        end
        table.sort(sortedActions, function(a, b) return a.name < b.name end)
        
        -- Create action items
        for _, actionData in ipairs(sortedActions) do
            local actionName = "Action_" .. actionData.name
            CreateWindowFromTemplate(actionName, "ActionItemTemplate", "VisualProgrammingInterfaceWindowScrollWindowLeftScrollChildLeft")
            WindowClearAnchors(actionName)
            WindowAddAnchor(actionName, "topleft", "VisualProgrammingInterfaceWindowScrollWindowLeftScrollChildLeft", "topleft", 0, yOffset)
            ButtonSetText(actionName, StringToWString(actionData.name))
            WindowSetId(actionName, actionData.name)
            yOffset = yOffset + 25
        end
        
        -- Add spacing after category
        yOffset = yOffset + 10
    end
    
    -- Update scroll child height
    WindowSetDimensions("VisualProgrammingInterfaceWindowScrollWindowLeftScrollChildLeft", 250, yOffset)
end

function VisualProgrammingInterface.BlockSelectionCallback()
    local actionName = SystemData.ActiveWindow.name:match("Action_(.+)$")
    if not actionName then return end
    
    VisualProgrammingInterface.ContextMenuCallback("add_block", actionName)
end
