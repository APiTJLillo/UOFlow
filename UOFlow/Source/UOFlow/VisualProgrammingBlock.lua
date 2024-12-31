-- Class for visual programming blocks
VisualProgrammingInterface.Block = {}
VisualProgrammingInterface.Block.__index = VisualProgrammingInterface.Block

function VisualProgrammingInterface.Block:new(id, blockType, x, y, column)
    local block = {
        id = id,
        type = blockType,
        x = x,
        y = y,
        column = column or "middle", -- middle or right
        isDragging = false,
        params = {},
        state = "pending", -- pending, running, completed, error
        connections = {} -- Array to store connections to other blocks
    }
    setmetatable(block, VisualProgrammingInterface.Block)
    
    -- Get action definition and create a deep copy of default parameters
    local action = VisualProgrammingInterface.Actions:get(blockType)
    if action then
        -- Deep copy default parameters to ensure each block has its own unique parameter set
        block.params = {}
        local defaultParams = VisualProgrammingInterface.Actions:getDefaultParams(blockType)
        if defaultParams then
            for k, v in pairs(defaultParams) do
                if type(v) == "table" then -- Now type() function works correctly
                    block.params[k] = {}
                    for k2, v2 in pairs(v) do
                        block.params[k][k2] = v2
                    end
                else
                    block.params[k] = v
                end
            end
        end
        block.description = action.description
        block.icon = action.icon
        -- Add instance identifier to help distinguish between blocks of same type
        block.instanceName = blockType .. " #" .. block.id
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
        
        -- Update both name and description
        local text = self:getDescription()
        
        -- Update name
        local name = blockWindow .. "Name"
        if DoesWindowNameExist(name) then
            LabelSetText(name, StringToWString(text))
        end
        
        -- Update description
        local description = blockWindow .. "Description"
        if DoesWindowNameExist(description) then
            LabelSetText(description, StringToWString(text))
        end
    end
end

function VisualProgrammingInterface.Block:getDescription()
    local action = VisualProgrammingInterface.Actions:get(self.type)
    if not action then return self.type end
    
    -- Start with action name
    local desc = action.name or self.type
    
    -- Build parameter description in specific order
    local paramValues = {}
    
    -- Handle parameters based on block type
    if action.name == "Cast Spell" then
        -- Special formatting for Cast Spell blocks: "SpellName → target"
        local spellName = self.params.spellId or ""
        local target = self.params.target or ""
        -- Remove any "Spell" suffix from spell names for cleaner display
        spellName = spellName:gsub(" Spell$", "")
        desc = desc .. " [" .. self.id .. "]: " .. spellName .. "(" .. target .. ")"
        -- Add state if not pending
        if self.state ~= "pending" then
            desc = desc .. " (" .. self.state .. ")"
        end
        return desc
    else
        -- For other blocks, add parameters in order
        for _, param in ipairs(action.params) do
            local value = self.params[param.name]
            if value ~= nil then
                if param.type == "boolean" then
                    value = (type(value) == "boolean" and value) or (value == "true") and "Yes" or "No"
                end
                table.insert(paramValues, tostring(value))
            end
        end
    end
    
    -- Build final description with instance number first
    desc = desc .. " [" .. self.id .. "]"
    
    -- Add parameters if any
    if #paramValues > 0 then
        desc = desc .. ": " .. table.concat(paramValues, ", ")
    end
    
    -- Add state if not pending
    if self.state ~= "pending" then
        desc = desc .. " (" .. self.state .. ")"
    end
    
    return desc
end

function VisualProgrammingInterface.Block:updateVisuals()
    local blockWindow = "Block" .. self.id
    if not DoesWindowNameExist(blockWindow) then return end
    
    -- Get action definition
    local action = VisualProgrammingInterface.Actions:get(self.type)
    if not action then return end
    
    -- Update name with full description
    local name = blockWindow .. "Name"
    if DoesWindowNameExist(name) then
        LabelSetText(name, StringToWString(self:getDescription()))
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
