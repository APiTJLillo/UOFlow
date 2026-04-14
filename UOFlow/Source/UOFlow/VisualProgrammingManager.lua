-- Class for managing visual programming interface
VisualProgrammingInterface.Manager = {}
VisualProgrammingInterface.Manager.__index = VisualProgrammingInterface.Manager

local function VPManagerColumnRank(block)
    if type(block) ~= "table" then
        return 0
    end
    if block.column == "right" then
        return 1
    end
    return 0
end

local function VPManagerSortBlocksByVisualOrder(a, b)
    local aRank = VPManagerColumnRank(a)
    local bRank = VPManagerColumnRank(b)
    if aRank ~= bRank then
        return aRank < bRank
    end

    local ay = tonumber(a and a.y) or 0
    local by = tonumber(b and b.y) or 0
    if ay ~= by then
        return ay < by
    end

    return (tonumber(a and a.id) or 0) < (tonumber(b and b.id) or 0)
end

function VisualProgrammingInterface.Manager:new()
    local manager = {
        blocks = {},
        nextBlockId = 1,
        blockTypes = {}
    }
    setmetatable(manager, VisualProgrammingInterface.Manager)
    return manager
end

function VisualProgrammingInterface.Manager:createBlock(type, x, y, column)
    local block = VisualProgrammingInterface.Block:new(self.nextBlockId, type, x, y, column)
    self.blocks[self.nextBlockId] = block
    self.nextBlockId = self.nextBlockId + 1
    return block
end

function VisualProgrammingInterface.Manager:removeBlock(id)
    -- Clean up any associated windows
    local block = self.blocks[id]
    if block then
        -- Clean up the block window and its children
        local blockName = "Block" .. id
        DestroyWindow(blockName)
        
        -- Clean up any associated property editors
        local rightScrollChild = "VisualProgrammingInterfaceWindowScrollWindowRightScrollChildRight"
        if DoesWindowNameExist(rightScrollChild) then
            local action = VisualProgrammingInterface.Actions:get(block.type)
            if action then
                for _, param in ipairs(action.params) do
                    local editBoxName = rightScrollChild .. "EditBox" .. param.name
                    if DoesWindowNameExist(editBoxName) then
                        DestroyWindow(editBoxName)
                    end
                end
            end
        end
    end
    
    -- Remove the block from our collection
    self.blocks[id] = nil
    
    -- Get all remaining blocks sorted by vertical position
    local sortedBlocks = {}
    for _, block in pairs(self.blocks) do
        table.insert(sortedBlocks, block)
    end
    table.sort(sortedBlocks, function(a, b) return a.y < b.y end)
    
    -- Reposition remaining blocks with proper spacing
    for index, block in ipairs(sortedBlocks) do
        local newY = (index - 1) * 80
        block.y = newY
        
        -- Update window position
        local blockName = "Block" .. block.id
        if DoesWindowNameExist(blockName) then
            WindowClearAnchors(blockName)
            local parentWindow = block.column == "right" and 
                "VisualProgrammingInterfaceWindowScrollWindowRightScrollChildRight" or 
                "VisualProgrammingInterfaceWindowScrollWindowScrollChild"
            WindowAddAnchor(blockName, "topleft", parentWindow, "topleft", 0, newY)
            WindowSetShowing(blockName, true)
            WindowSetLayer(blockName, Window.Layers.DEFAULT)
        end
    end
    
    -- Update scroll child heights based on number of remaining blocks in each column
    local middleBlocks = 0
    local rightBlocks = 0
    for _, b in pairs(sortedBlocks) do
        if b.column == "right" then
            rightBlocks = rightBlocks + 1
        else
            middleBlocks = middleBlocks + 1
        end
    end
    
    -- Update middle column
    local middleScrollChild = "VisualProgrammingInterfaceWindowScrollWindowScrollChild"
    local middleHeight = math.max(middleBlocks * 80, 80)
    WindowSetDimensions(middleScrollChild, 300, middleHeight)
    ScrollWindowUpdateScrollRect("VisualProgrammingInterfaceWindowScrollWindow")
    
    -- Update right column
    local rightScrollChild = "VisualProgrammingInterfaceWindowScrollWindowRightScrollChildRight"
    local rightHeight = math.max(rightBlocks * 80, 80)
    WindowSetDimensions(rightScrollChild, 300, rightHeight)
    ScrollWindowUpdateScrollRect("VisualProgrammingInterfaceWindowScrollWindowRight")

    self:rebuildLinearConnectionsFromVisualOrder()
end

function VisualProgrammingInterface.Manager:getBlock(id)
    return self.blocks[id]
end

function VisualProgrammingInterface.Manager:getBlocksInVisualOrder()
    local sortedBlocks = {}
    for _, block in pairs(self.blocks) do
        if type(block) == "table" then
            table.insert(sortedBlocks, block)
        end
    end
    table.sort(sortedBlocks, VPManagerSortBlocksByVisualOrder)
    return sortedBlocks
end

function VisualProgrammingInterface.Manager:rebuildLinearConnectionsFromVisualOrder()
    local sortedBlocks = self:getBlocksInVisualOrder()
    local orderedIds = {}

    for _, block in ipairs(sortedBlocks) do
        table.insert(orderedIds, tostring(block.id))
    end

    if type(UOWNativeLog) == "function" then
        UOWNativeLog("[VPExec] rebuilt visual order", table.concat(orderedIds, ","))
    end

    return sortedBlocks
end

function VisualProgrammingInterface.Manager:addBlockType(type, icon)
    self.blockTypes[type] = icon
end

function VisualProgrammingInterface.Manager:saveConfiguration()
    local config = {}
    for id, block in pairs(self.blocks) do
        table.insert(config, {
            id = block.id,
            type = block.type,
            x = block.x,
            y = block.y,
            column = block.column
        })
    end
    return config
end

function VisualProgrammingInterface.Manager:loadConfiguration(config)
    self.blocks = {}
    for _, blockData in ipairs(config) do
        local block = VisualProgrammingInterface.Block:new(
            blockData.id, 
            blockData.type, 
            blockData.x, 
            blockData.y,
            blockData.column or "middle" -- Default to middle for backward compatibility
        )
        self.blocks[blockData.id] = block
    end
end
