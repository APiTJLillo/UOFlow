-- Class for visual programming blocks
VisualProgrammingInterface.Block = {}
VisualProgrammingInterface.Block.__index = VisualProgrammingInterface.Block

function VisualProgrammingInterface.Block:new(id, type, x, y, column)
    local block = {
        id = id,
        type = type,
        x = x,
        y = y,
        column = column or "middle", -- middle or right
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
            -- Convert value to string based on parameter type
            local displayValue
            if param.type == "number" then
                -- Ensure numeric values are properly formatted
                if type(value) == "number" then
                    displayValue = tostring(value)
                else
                    local num = tonumber(value)
                    displayValue = num and tostring(num) or "0"
                end
            elseif param.type == "boolean" then
                -- Handle boolean values
                if type(value) == "boolean" then
                    displayValue = value and "true" or "false"
                else
                    displayValue = value == "true" and "true" or "false"
                end
            else
                -- Handle string values
                displayValue = tostring(value)
            end
            
            -- Add to parameter descriptions
            if displayValue then
                table.insert(paramDesc, param.name .. ": " .. displayValue)
            end
        end
    end
    
    -- Build final description
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
        
        -- Update column based on x position
        local windowX = WindowGetScreenPosition("VisualProgrammingInterfaceWindowScrollWindowRight")
        if windowX and x > windowX then
            self.column = "right"
        else
            self.column = "middle"
        end
    end
end

-- Helper function to get the parent window name based on column
function VisualProgrammingInterface.Block:getParentWindow()
    return self.column == "right" and 
        "VisualProgrammingInterfaceWindowScrollWindowRightScrollChildRight" or 
        "VisualProgrammingInterfaceWindowScrollWindowScrollChild"
end
