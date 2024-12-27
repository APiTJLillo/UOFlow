-- Class for visual programming blocks
VisualProgrammingInterface.Block = {}
VisualProgrammingInterface.Block.__index = VisualProgrammingInterface.Block

function VisualProgrammingInterface.Block:new(id, type, x, y)
    local block = {
        id = id,
        type = type,
        x = x,
        y = y,
        connections = {},
        isDragging = false,
        params = {},
        state = "pending" -- pending, running, completed, error
    }
    setmetatable(block, VisualProgrammingInterface.Block)
    
    -- Get action definition and set default parameters
    local action = VisualProgrammingInterface.Actions:get(type)
    if action then
        block.params = VisualProgrammingInterface.Actions:getDefaultParams(type)
        block.description = action.description
        block.icon = action.icon
    end
    
    return block
end

function VisualProgrammingInterface.Block:setState(state)
    self.state = state
    local blockWindow = "Block" .. self.id
    
    if DoesWindowNameExist(blockWindow) then
        -- Update block visual state
        if state == "running" then
            WindowSetTintColor(blockWindow, 243, 227, 49) -- UO Gold for running
        elseif state == "completed" then
            WindowSetTintColor(blockWindow, 159, 177, 189) -- UO Blue for completed
        elseif state == "error" then
            WindowSetTintColor(blockWindow, 155, 0, 0) -- UO Red for error
        else -- pending
            WindowSetTintColor(blockWindow, 206, 217, 242) -- UO Default text color for pending
        end
        
        -- Update description text
        local description = blockWindow .. "Description"
        if DoesWindowNameExist(description) then
            local text = self:getDescription()
            if state == "error" then
                text = text .. " (Error)"
            elseif state == "completed" then
                text = text .. " (Completed)"
            end
            LabelSetText(description, StringToWString(text))
        end
    end
end

function VisualProgrammingInterface.Block:getDescription()
    local action = VisualProgrammingInterface.Actions:get(self.type)
    if not action then return self.type end
    
    local desc = action.description or self.type
    local paramDesc = {}
    
    -- Add parameter values to description
    for _, param in ipairs(action.params) do
        local value = self.params[param.name]
        if value ~= nil then
            table.insert(paramDesc, param.name .. ": " .. tostring(value))
        end
    end
    
    if #paramDesc > 0 then
        desc = desc .. " (" .. table.concat(paramDesc, ", ") .. ")"
    end
    
    -- Add state if not pending
    if self.state ~= "pending" then
        desc = desc .. " [" .. self.state .. "]"
    end
    
    return desc
end

function VisualProgrammingInterface.Block:updateVisuals()
    local blockWindow = "Block" .. self.id
    if not DoesWindowNameExist(blockWindow) then return end
    
    -- Get action definition
    local action = VisualProgrammingInterface.Actions:get(self.type)
    if not action then return end
    
    -- Update name
    local name = blockWindow .. "Name"
    if DoesWindowNameExist(name) then
        LabelSetText(name, StringToWString(action.name or self.type))
    end
    
    -- Update description
    local description = blockWindow .. "Description"
    if DoesWindowNameExist(description) then
        LabelSetText(description, StringToWString(self:getDescription()))
    end
    
    -- Update icon if available
    local icon = blockWindow .. "Icon"
    if DoesWindowNameExist(icon) and action.icon then
        DynamicImageSetTexture(icon, action.icon, 0, 0)
    end
    
    -- Update color based on state
    if self.state == "running" then
        WindowSetTintColor(blockWindow, 243, 227, 49) -- UO Gold for running
    elseif self.state == "completed" then
        WindowSetTintColor(blockWindow, 159, 177, 189) -- UO Blue for completed
    elseif self.state == "error" then
        WindowSetTintColor(blockWindow, 155, 0, 0) -- UO Red for error
    else
        WindowSetTintColor(blockWindow, 206, 217, 242) -- UO Default text color for pending
    end
end

function VisualProgrammingInterface.Block:addConnection(targetBlock)
    table.insert(self.connections, targetBlock)
end

function VisualProgrammingInterface.Block:startDrag()
    self.isDragging = true
end

function VisualProgrammingInterface.Block:stopDrag()
    self.isDragging = false
end

function VisualProgrammingInterface.Block:drag(x, y)
    if self.isDragging then
        self.x = x
        self.y = y
        -- Update connections when block is dragged
        VisualProgrammingInterface.UpdateConnections()
    end
end

function VisualProgrammingInterface.Block:drawConnections()
    for _, connection in ipairs(self.connections) do
        local sourceBlock = "Block" .. self.id
        local targetBlock = "Block" .. connection.id
        
        if DoesWindowNameExist(sourceBlock) and DoesWindowNameExist(targetBlock) then
            -- Get block positions relative to scroll child
            local sourceX = 0  -- All blocks are aligned to left
            local sourceY = self.y
            local targetY = connection.y
            
            -- Calculate relative positions for arrow
            local dx = 840  -- Full width of block
            local dy = targetY - sourceY
            
            -- Clean up old arrow if it exists
            local arrowName = "Arrow_" .. self.id .. "_" .. connection.id
            if DoesWindowNameExist(arrowName) then
                DestroyWindow(arrowName)
            end
            
            -- Create new arrow
            CreateWindowFromTemplate(arrowName, "ArrowTemplate", "VisualProgrammingInterfaceWindowScrollWindowScrollChild")
            
            -- Set up the line using UO horizontal rule
            local arrowLine = arrowName .. "Line"
            WindowSetTintColor(arrowLine, 206, 217, 242) -- UO Default text color
            WindowSetAlpha(arrowLine, 0.8)
            WindowSetShowing(arrowLine, true)
            WindowSetLayer(arrowLine, Window.Layers.OVERLAY)

            
            -- Calculate arrow dimensions
            local length = math.sqrt(dx * dx + dy * dy)
            local angle = math.atan2(dy, dx)
            
            -- Position the arrow
            WindowClearAnchors(arrowName)
            WindowAddAnchor(arrowName, "center", sourceBlock, "right", 20, 35)
            WindowSetDimensions(arrowName, length - 40, 32)
            WindowSetShowing(arrowName, true)
            WindowSetLayer(arrowName, Window.Layers.OVERLAY)
            
            -- Update arrow line
            if DoesWindowNameExist(arrowLine) then
                WindowSetDimensions(arrowLine, length - 40, 8)
                WindowSetShowing(arrowLine, true)
                WindowSetLayer(arrowLine, Window.Layers.OVERLAY)
            end
        end
    end
end
