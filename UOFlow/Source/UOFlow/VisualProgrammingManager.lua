-- Class for managing visual programming interface
VisualProgrammingInterface.Manager = {}
VisualProgrammingInterface.Manager.__index = VisualProgrammingInterface.Manager

function VisualProgrammingInterface.Manager:new()
    local manager = {
        blocks = {},
        nextBlockId = 1,
        blockTypes = {}
    }
    setmetatable(manager, VisualProgrammingInterface.Manager)
    return manager
end

function VisualProgrammingInterface.Manager:createBlock(type, x, y)
    local block = VisualProgrammingInterface.Block:new(self.nextBlockId, type, x, y)
    self.blocks[self.nextBlockId] = block
    self.nextBlockId = self.nextBlockId + 1
    return block
end

function VisualProgrammingInterface.Manager:removeBlock(id)
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
            WindowAddAnchor(blockName, "topleft", "VisualProgrammingInterfaceWindowScrollWindowScrollChild", "topleft", 0, newY)
            WindowSetShowing(blockName, true)
            WindowSetLayer(blockName, Window.Layers.DEFAULT)
        end
    end
    
    -- Update scroll child height based on number of remaining blocks
    local scrollChild = "VisualProgrammingInterfaceWindowScrollWindowScrollChild"
    local newHeight = math.max(#sortedBlocks * 80, 80)
    WindowSetDimensions(scrollChild, 840, newHeight)
    
    -- Update scroll window to reflect new content size
    ScrollWindowUpdateScrollRect("VisualProgrammingInterfaceWindowScrollWindow")
    
end

function VisualProgrammingInterface.Manager:getBlock(id)
    return self.blocks[id]
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
            y = block.y
        })
    end
    return config
end

function VisualProgrammingInterface.Manager:loadConfiguration(config)
    self.blocks = {}
    for _, blockData in ipairs(config) do
        local block = VisualProgrammingInterface.Block:new(blockData.id, blockData.type, blockData.x, blockData.y)
        self.blocks[blockData.id] = block
    end
end
