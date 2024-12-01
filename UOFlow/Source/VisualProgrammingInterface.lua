-- VisualProgrammingInterface.lua

VisualProgrammingInterface = {}

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
        isDragging = false
    }
    setmetatable(block, VisualProgrammingInterface.Block)
    return block
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
    end
end

function VisualProgrammingInterface.Block:showContextMenu()
    -- Show context menu with options: edit, delete, add connection
end

function VisualProgrammingInterface.Block:drawConnections()
    for _, connection in ipairs(self.connections) do
        -- Draw line or arrow from this block to the connected block
    end
end

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
    self.blocks[id] = nil
end

function VisualProgrammingInterface.Manager:getBlock(id)
    return self.blocks[id]
end

function VisualProgrammingInterface.Manager:connectBlocks(sourceId, targetId)
    local sourceBlock = self:getBlock(sourceId)
    local targetBlock = self:getBlock(targetId)
    if sourceBlock and targetBlock then
        sourceBlock:addConnection(targetBlock)
    end
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
            connections = block.connections
        })
    end
    return config
end

function VisualProgrammingInterface.Manager:loadConfiguration(config)
    self.blocks = {}
    for _, blockData in ipairs(config) do
        local block = VisualProgrammingInterface.Block:new(blockData.id, blockData.type, blockData.x, blockData.y)
        block.connections = blockData.connections
        self.blocks[blockData.id] = block
    end
end

-- Initialize the visual programming interface
function VisualProgrammingInterface.Initialize()
    VisualProgrammingInterface.manager = VisualProgrammingInterface.Manager:new()
end

-- Show the visual programming interface window
function VisualProgrammingInterface.Show()
    if not DoesWindowNameExist("VisualProgrammingInterfaceWindow") then
        CreateWindow("VisualProgrammingInterfaceWindow", true)
    end
    WindowSetShowing("VisualProgrammingInterfaceWindow", true)
end

-- Hide the visual programming interface window
function VisualProgrammingInterface.Hide()
    if DoesWindowNameExist("VisualProgrammingInterfaceWindow") then
        WindowSetShowing("VisualProgrammingInterfaceWindow", false)
    end
end

-- Toggle the visual programming interface window
function VisualProgrammingInterface.Toggle()
    if DoesWindowNameExist("VisualProgrammingInterfaceWindow") and WindowGetShowing("VisualProgrammingInterfaceWindow") then
        VisualProgrammingInterface.Hide()
    else
        VisualProgrammingInterface.Show()
    end
end
