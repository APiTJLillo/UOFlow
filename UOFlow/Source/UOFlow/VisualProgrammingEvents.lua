-- Event Handlers for Visual Programming Interface

function VisualProgrammingInterface.OnBlockRButtonUp()
    local blockName = SystemData.ActiveWindow.name:gsub("Icon$", ""):gsub("Name$", ""):gsub("Description$", "")
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
    local blockName = SystemData.ActiveWindow.name:gsub("Icon$", ""):gsub("Name$", ""):gsub("Description$", "")
    local block = VisualProgrammingInterface.manager:getBlock(tonumber(blockName:match("%d+")))
    if block then
        block:startDrag()
        
        -- Store initial positions
        local mouseY = SystemData.MousePosition.y
        
        -- Store drag offset as distance from mouse to block's current Y position
        VisualProgrammingInterface.dragStartY = block.y
        VisualProgrammingInterface.dragMouseStartY = mouseY
        VisualProgrammingInterface.dragStartColumn = block.column
        
        -- Store column positions
        local middleX = WindowGetScreenPosition("VisualProgrammingInterfaceWindowScrollWindow")
        local rightX = WindowGetScreenPosition("VisualProgrammingInterfaceWindowScrollWindowRight")
        local middleWidth = WindowGetDimensions("VisualProgrammingInterfaceWindowScrollWindow")
        local rightWidth = WindowGetDimensions("VisualProgrammingInterfaceWindowScrollWindowRight")
        
        -- Calculate column boundaries and switch points
        VisualProgrammingInterface.columnX = {
            middle = {x = middleX, width = middleWidth},
            right = {x = rightX, width = rightWidth},
            switchPoint = rightX - 50, -- point at which to switch columns
            threshold = 75 -- additional pixels needed to switch
        }
    end
end

-- Helper function to get block slot based on Y position
function VisualProgrammingInterface.GetSlotFromY(y, blocks)
    local slotHeight = 80 -- Height of each block slot
    local slot = math.floor(y / slotHeight)
    return math.max(0, slot)
end

-- Helper function to get Y position from slot
function VisualProgrammingInterface.GetYFromSlot(slot)
    return slot * 80
end

-- Helper function to animate blocks shifting
function VisualProgrammingInterface.AnimateBlockShift(block, targetY)
    -- Simply move block to target position
    block.y = targetY
    local blockWindow = "Block" .. block.id
    if DoesWindowNameExist(blockWindow) then
        WindowClearAnchors(blockWindow)
        local parentWindow = block.column == "right" and 
            "VisualProgrammingInterfaceWindowScrollWindowRightScrollChildRight" or 
            "VisualProgrammingInterfaceWindowScrollWindowScrollChild"
        WindowAddAnchor(blockWindow, "topleft", parentWindow, "topleft", 0, targetY)
    end
end

function VisualProgrammingInterface.OnBlockDrag()
    local blockName = SystemData.ActiveWindow.name:gsub("Icon$", ""):gsub("Name$", ""):gsub("Description$", "")
    local block = VisualProgrammingInterface.manager:getBlock(tonumber(blockName:match("Block(%d+)")))
    
    if not block or not block.isDragging then return end
    
    -- Calculate new position
    local mouseX = SystemData.MousePosition.x
    local mouseY = SystemData.MousePosition.y
    local deltaY = mouseY - VisualProgrammingInterface.dragMouseStartY
    
    -- Calculate new Y position relative to start
    local newY = VisualProgrammingInterface.dragStartY + deltaY
    
    -- Determine target column based on mouse position with hysteresis
    local targetColumn = block.column
    local cols = VisualProgrammingInterface.columnX
    
    -- Only switch columns when significantly past the boundary
    if block.column == "middle" then
        if mouseX > cols.switchPoint + cols.threshold then
            targetColumn = "right"
        end
    else -- right column
        if mouseX < cols.switchPoint - cols.threshold then
            targetColumn = "middle"
        end
    end
    
    -- Get scroll window and scroll child
    local scrollWindow = targetColumn == "right" and 
        "VisualProgrammingInterfaceWindowScrollWindowRight" or 
        "VisualProgrammingInterfaceWindowScrollWindow"
    local scrollChild = targetColumn == "right" and 
        "VisualProgrammingInterfaceWindowScrollWindowRightScrollChildRight" or 
        "VisualProgrammingInterfaceWindowScrollWindowScrollChild"
    
    -- Get scroll position and dimensions
    local scrollOffset = ScrollWindowGetOffset(scrollWindow) or 0
    local _, _, _, scrollHeight = WindowGetDimensions(scrollWindow)
    local _, _, _, childHeight = WindowGetDimensions(scrollChild)
    
    -- Default values if dimensions are nil
    scrollHeight = scrollHeight or 600
    childHeight = childHeight or 1200
    
    -- Calculate visible area bounds
    local visibleTop = scrollOffset
    local visibleBottom = scrollOffset + scrollHeight
    
    -- Allow movement in both directions but constrain to scroll area
    local adjustedY = newY + scrollOffset
    
    -- If dragging near the top/bottom edges, adjust scroll position
    if adjustedY < visibleTop + 80 then
        ScrollWindowSetOffset(scrollWindow, math.max(0, scrollOffset - 40))
        ScrollWindowUpdateScrollRect(scrollWindow)
    elseif adjustedY > visibleBottom - 80 then
        ScrollWindowSetOffset(scrollWindow, math.min(childHeight - scrollHeight, scrollOffset + 40))
        ScrollWindowUpdateScrollRect(scrollWindow)
    end
    
    -- Update scroll offset after potential change
    scrollOffset = ScrollWindowGetOffset(scrollWindow) or 0
    
    -- Constrain position to scroll area bounds
    newY = math.max(-scrollHeight, math.min(childHeight - 80, adjustedY)) - scrollOffset
    
    -- Calculate slot position with snapping
    local slotHeight = 80
    local snapThreshold = slotHeight / 4
    local nearestSlot = math.floor((adjustedY + snapThreshold) / slotHeight)
    local snappedY = nearestSlot * slotHeight - scrollOffset
    
    -- Apply snapping if close to slot boundary
    if math.abs(adjustedY - (snappedY + scrollOffset)) < snapThreshold then
        newY = snappedY
    end
    
    -- Update dragged block position and column
    local oldColumn = block.column
    block.column = targetColumn
    WindowClearAnchors(blockName)
    local parentWindow = targetColumn == "right" and 
        "VisualProgrammingInterfaceWindowScrollWindowRightScrollChildRight" or 
        "VisualProgrammingInterfaceWindowScrollWindowScrollChild"
    WindowAddAnchor(blockName, "topleft", parentWindow, "topleft", 0, newY)
    block.y = newY
    
    -- Get blocks in both columns
    local middleBlocks = {}
    local rightBlocks = {}
    for _, b in pairs(VisualProgrammingInterface.manager.blocks) do
        if b.id ~= block.id then
            if b.column == "middle" then
                table.insert(middleBlocks, b)
            else
                table.insert(rightBlocks, b)
            end
        end
    end
    
    -- Sort blocks by Y position
    table.sort(middleBlocks, function(a, b) return a.y < b.y end)
    table.sort(rightBlocks, function(a, b) return a.y < b.y end)
    
    -- Function to update blocks in a column
    local function updateColumnBlocks(blocks, targetBlock)
        local currentSlot = 0
        for _, b in ipairs(blocks) do
            if targetBlock and currentSlot == nearestSlot then
                currentSlot = currentSlot + 1
            end
            
            local targetY = VisualProgrammingInterface.GetYFromSlot(currentSlot) - scrollOffset
            if math.abs(b.y - targetY) > 1 then
                VisualProgrammingInterface.AnimateBlockShift(b, targetY)
            end
            
            currentSlot = currentSlot + 1
        end
    end
    
    -- Update blocks in both columns
    updateColumnBlocks(middleBlocks, targetColumn == "middle" and block or nil)
    updateColumnBlocks(rightBlocks, targetColumn == "right" and block or nil)
    
    -- Update scroll windows if column changed
    if oldColumn ~= targetColumn then
        ScrollWindowUpdateScrollRect("VisualProgrammingInterfaceWindowScrollWindow")
        ScrollWindowUpdateScrollRect("VisualProgrammingInterfaceWindowScrollWindowRight")
    end
end

function VisualProgrammingInterface.OnBlockDragEnd()
    local blockName = SystemData.ActiveWindow.name:gsub("Icon$", ""):gsub("Name$", ""):gsub("Description$", "")
    local block = VisualProgrammingInterface.manager:getBlock(tonumber(blockName:match("Block(%d+)")))
    
    if not block then return end
    
    block:stopDrag()
    
    -- Use the same column switching logic as drag
    local mouseX = SystemData.MousePosition.x
    local switchPoint = VisualProgrammingInterface.columnX.right
    local threshold = VisualProgrammingInterface.columnX.threshold
    local targetColumn = block.column
    
    -- Keep current column unless we've moved significantly
    if block.column == "middle" then
        if mouseX > switchPoint + threshold then
            targetColumn = "right"
        end
    else -- right column
        if mouseX < switchPoint - threshold then
            targetColumn = "middle"
        end
    end
    
    -- Get blocks in target column
    local columnBlocks = {}
    for _, b in pairs(VisualProgrammingInterface.manager.blocks) do
        if b.id ~= block.id and b.column == targetColumn then
            table.insert(columnBlocks, b)
        end
    end
    table.sort(columnBlocks, function(a, b) return a.y < b.y end)
    
    -- Get scroll window and scroll child
    local scrollWindow = targetColumn == "right" and 
        "VisualProgrammingInterfaceWindowScrollWindowRight" or 
        "VisualProgrammingInterfaceWindowScrollWindow"
    local scrollChild = targetColumn == "right" and 
        "VisualProgrammingInterfaceWindowScrollWindowRightScrollChildRight" or 
        "VisualProgrammingInterfaceWindowScrollWindowScrollChild"
    
    -- Get scroll position
    local scrollOffset = ScrollWindowGetOffset(scrollWindow)
    
    -- Calculate target slot based on final position with scroll offset
    local adjustedY = block.y + scrollOffset
    local targetSlot = VisualProgrammingInterface.GetSlotFromY(adjustedY, columnBlocks)
    
    -- Update block's column if it changed
    if block.column ~= targetColumn then
        block.column = targetColumn
        local parentWindow = targetColumn == "right" and 
            "VisualProgrammingInterfaceWindowScrollWindowRightScrollChildRight" or 
            "VisualProgrammingInterfaceWindowScrollWindowScrollChild"
        
        WindowClearAnchors(blockName)
        WindowAddAnchor(blockName, "topleft", parentWindow, "topleft", 0, block.y)
    end
    
    -- Reposition all blocks with animation
    table.insert(columnBlocks, targetSlot + 1, block)
    
    for index, b in ipairs(columnBlocks) do
        local targetY = VisualProgrammingInterface.GetYFromSlot(index - 1) - scrollOffset
        if math.abs(b.y - targetY) > 1 then
            VisualProgrammingInterface.AnimateBlockShift(b, targetY)
        end
    end
    
    -- Update scroll windows
    ScrollWindowUpdateScrollRect("VisualProgrammingInterfaceWindowScrollWindow")
    ScrollWindowUpdateScrollRect("VisualProgrammingInterfaceWindowScrollWindowRight")
end

function VisualProgrammingInterface.ContextMenuCallback(returnCode, param)
    if returnCode == "delete" then
        local blockId = tonumber(param:gsub("Icon$", ""):gsub("Name$", ""):gsub("Description$", ""):match("Block(%d+)"))
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
                -- Get scroll window for block's column
                local scrollWindow = b.column == "right" and 
                    "VisualProgrammingInterfaceWindowScrollWindowRight" or 
                    "VisualProgrammingInterfaceWindowScrollWindow"
                local scrollOffset = ScrollWindowGetOffset(scrollWindow)
                
                -- Calculate new position with scroll offset
                local newY = (index - 1) * 80 - scrollOffset
                b.y = newY
                
                local bName = "Block" .. b.id
                if DoesWindowNameExist(bName) then
                    WindowClearAnchors(bName)
                    local parentWindow = b.column == "right" and 
                        "VisualProgrammingInterfaceWindowScrollWindowRightScrollChildRight" or 
                        "VisualProgrammingInterfaceWindowScrollWindowScrollChild"
                    WindowAddAnchor(bName, "topleft", parentWindow, "topleft", 0, newY)
                end
            end
            
        end
    end
end

-- Config Window Event Handlers
function VisualProgrammingInterface.OnBlockClick()
    local blockName = SystemData.ActiveWindow.name
    -- Remove any suffixes (Icon, Name, Description) to get base block name
    blockName = blockName:gsub("Icon$", ""):gsub("Name$", ""):gsub("Description$", "")
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
        local editBoxName = rightScrollChild .. "EditBox" .. param.name
        CreateWindowFromTemplate(editBoxName, "UO_DefaultTextInput", rightScrollChild)
        if DoesWindowNameExist(editBoxName) then
            WindowClearAnchors(editBoxName)
            WindowAddAnchor(editBoxName, "topleft", rightScrollChild, "topleft", 20, yOffset)
            
            -- Set text and store block ID
            TextEditBoxSetText(editBoxName, StringToWString(tostring(block.params[param.name] or "")))
            WindowSetId(editBoxName, blockId)
            
            -- Enable editing
            WindowSetHandleInput(editBoxName, true)
        end
        
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
    
    local paramName = SystemData.ActiveWindow.name:match("EditBox([^T]+)$")
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
            WindowAddAnchor(actionName, "topleft", "VisualProgrammingInterfaceWindowScrollWindowLeftScrollChildLeft", "topleft", 20, yOffset)
            ButtonSetText(actionName, StringToWString(actionData.name))
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
