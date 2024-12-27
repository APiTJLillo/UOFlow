-- Event Handlers for Visual Programming Interface

function VisualProgrammingInterface.OnBlockRButtonUp()
    local blockName = SystemData.ActiveWindow.name:gsub("Icon$", "")
    local blockId = tonumber(blockName:match("Block(%d+)"))
    
    if not blockId then return end
    
    local block = VisualProgrammingInterface.manager:getBlock(blockId)
    if not block then return end
    
    local contextMenuOptions = {
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
        local parentWindow = block.column == "right" and "VisualProgrammingInterfaceWindowScrollWindowRightScrollChildRight" or "VisualProgrammingInterfaceWindowScrollWindowScrollChild"
        WindowAddAnchor(blockName, "topleft", parentWindow, "topleft", 0, newY)
        
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
                local parentWindow = b.column == "right" and "VisualProgrammingInterfaceWindowScrollWindowRightScrollChildRight" or "VisualProgrammingInterfaceWindowScrollWindowScrollChild"
                WindowAddAnchor(bName, "topleft", parentWindow, "topleft", 0, newY)
            end
        end
        
    end
end

function VisualProgrammingInterface.ContextMenuCallback(returnCode, param)
    if returnCode == "delete" then
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
        
        -- Determine which column to place the block in
        local targetColumn = #sortedBlocks % 2 == 0 and "middle" or "right"
        local block = VisualProgrammingInterface.CreateBlock(param, newIndex, targetColumn)
        if block then
            Debug.Print("Successfully created block with ID: " .. tostring(block.id))
            if targetColumn == "right" then
                ScrollWindowUpdateScrollRect("VisualProgrammingInterfaceWindowScrollWindowRight")
            else
                ScrollWindowUpdateScrollRect("VisualProgrammingInterfaceWindowScrollWindow")
            end
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
                    local parentWindow = b.column == "right" and "VisualProgrammingInterfaceWindowScrollWindowRightScrollChildRight" or "VisualProgrammingInterfaceWindowScrollWindowScrollChild"
                WindowAddAnchor(bName, "topleft", parentWindow, "topleft", 0, newY)
                end
            end
            
        end
    end
end

-- Config Window Event Handlers
function VisualProgrammingInterface.OnBlockClick()
    local blockName = SystemData.ActiveWindow.name:gsub("Icon$", "")
    local blockId = tonumber(blockName:match("Block(%d+)"))
    
    if not blockId then return end
    
    local block = VisualProgrammingInterface.manager:getBlock(blockId)
    if not block then return end
    
    -- Clear existing properties
    local rightScrollChild = "VisualProgrammingInterfaceWindowScrollWindowRightScrollChildRight"
    DestroyWindow(rightScrollChild)
    CreateWindowFromTemplate(rightScrollChild, "ScrollChild", "VisualProgrammingInterfaceWindowScrollWindowRight")
    
    -- Get action definition
    local action = VisualProgrammingInterface.Actions:get(block.type)
    if not action then return end
    
    -- Create property editors
    local yOffset = 10
    
    -- Add block type header
    local headerName = rightScrollChild .. "Header"
    CreateWindowFromTemplate(headerName, "CategoryHeaderTemplate", rightScrollChild)
    WindowClearAnchors(headerName)
    WindowAddAnchor(headerName, "topleft", rightScrollChild, "topleft", 0, yOffset)
    LabelSetText(headerName .. "Text", StringToWString(block.type))
    yOffset = yOffset + 30
    
    -- Add property editors
    for _, param in ipairs(action.params) do
        -- Create label
        local labelName = rightScrollChild .. "Label" .. param.name
        CreateWindowFromTemplate(labelName, "CategoryHeaderTemplate", rightScrollChild)
        WindowClearAnchors(labelName)
        WindowAddAnchor(labelName, "topleft", rightScrollChild, "topleft", 10, yOffset)
        LabelSetText(labelName .. "Text", StringToWString(param.name))
        yOffset = yOffset + 25
        
        -- Create input field
        local inputName = rightScrollChild .. "Input" .. param.name
        CreateWindowFromTemplate(inputName, "UO_DefaultTextInput", rightScrollChild)
        WindowClearAnchors(inputName)
        WindowAddAnchor(inputName, "topleft", rightScrollChild, "topleft", 10, yOffset)
        WindowSetDimensions(inputName, 260, 25)
        TextEditBoxSetText(inputName, StringToWString(tostring(block.params[param.name] or "")))
        
        -- Add event handler for value changes
        WindowSetId(inputName, blockId)
        WindowAssignFocus(inputName, true)
        CreateEventHandler(inputName, "OnTextChanged", "VisualProgrammingInterface.OnPropertyChanged")
        
        yOffset = yOffset + 35
    end
    
    -- Update scroll child height
    WindowSetDimensions(rightScrollChild, 300, math.max(yOffset, 80))
    ScrollWindowUpdateScrollRect("VisualProgrammingInterfaceWindowScrollWindowRight")
end

function VisualProgrammingInterface.OnPropertyChanged()
    local blockId = WindowGetId(SystemData.ActiveWindow.name)
    local block = VisualProgrammingInterface.manager:getBlock(blockId)
    if not block then return end
    
    local paramName = SystemData.ActiveWindow.name:match("Input(.+)$")
    if not paramName then return end
    
    local newValue = WStringToString(TextEditBoxGetText(SystemData.ActiveWindow.name))
    block.params[paramName] = newValue
    block:updateVisuals()
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
