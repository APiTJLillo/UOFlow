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
        connections = {}
    }
    setmetatable(block, VisualProgrammingInterface.Block)
    return block
end

function VisualProgrammingInterface.Block:addConnection(targetBlock)
    table.insert(self.connections, targetBlock)
end

-- Class for managing visual programming interface
VisualProgrammingInterface.Manager = {}
VisualProgrammingInterface.Manager.__index = VisualProgrammingInterface.Manager

function VisualProgrammingInterface.Manager:new()
    local manager = {
        blocks = {},
        nextBlockId = 1
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
