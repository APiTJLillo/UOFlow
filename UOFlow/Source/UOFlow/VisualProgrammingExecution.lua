-- Execution engine for Visual Programming Interface

VisualProgrammingInterface.Execution = {
    isRunning = false,
    isPaused = false,
    currentBlock = nil,
    executionQueue = {},
    blockStates = {}, -- Stores execution state for each block
    delay = 1000, -- Default delay between blocks in ms
}

-- Block execution states
local BlockState = {
    PENDING = "pending",
    RUNNING = "running",
    COMPLETED = "completed",
    ERROR = "error"
}

-- Execute a single block
function VisualProgrammingInterface.Execution:executeBlock(block)
    if not block then return false end
    
    -- Update block state
    self.blockStates[block.id] = BlockState.RUNNING
    self.currentBlock = block
    
    -- Update visual state
    local blockWindow = "Block" .. block.id
    if DoesWindowNameExist(blockWindow) then
        WindowSetTintColor(blockWindow, 255, 255, 0) -- Yellow during execution
    end
    
    -- Get action definition
    local action = VisualProgrammingInterface.Actions:get(block.type)
    if not action then
        self.blockStates[block.id] = BlockState.ERROR
        if DoesWindowNameExist(blockWindow) then
            WindowSetTintColor(blockWindow, 255, 0, 0) -- Red for error
        end
        Debug.Print("Unknown action type: " .. block.type)
        return false
    end
    
    -- Validate parameters
    local isValid, error = VisualProgrammingInterface.Actions:validateParams(block.type, block.params)
    if not isValid then
        self.blockStates[block.id] = BlockState.ERROR
        if DoesWindowNameExist(blockWindow) then
            WindowSetTintColor(blockWindow, 255, 0, 0) -- Red for error
        end
        Debug.Print("Parameter validation failed: " .. tostring(error))
        return false
    end
    
    -- Execute action
    local success, error = VisualProgrammingInterface.Actions:execute(block.type, block.params)
    
    -- Update block state based on execution result
    if success then
        self.blockStates[block.id] = BlockState.COMPLETED
        if DoesWindowNameExist(blockWindow) then
            WindowSetTintColor(blockWindow, 0, 255, 0) -- Green for success
        end
    else
        self.blockStates[block.id] = BlockState.ERROR
        if DoesWindowNameExist(blockWindow) then
            WindowSetTintColor(blockWindow, 255, 0, 0) -- Red for error
        end
        Debug.Print("Block execution error: " .. (errorMsg or "Unknown error"))
    end
    
    return success
end

-- Start execution of the block sequence
function VisualProgrammingInterface.Execution:start()
    if self.isRunning then return end
    
    -- Reset states
    self.isRunning = true
    self.isPaused = false
    self.blockStates = {}
    self.executionQueue = {}
    
    -- Reset visual states
    for id, _ in pairs(VisualProgrammingInterface.manager.blocks) do
        local blockWindow = "Block" .. id
        if DoesWindowNameExist(blockWindow) then
            WindowSetTintColor(blockWindow, 255, 255, 255) -- Reset to white
        end
        self.blockStates[id] = BlockState.PENDING
    end
    
    -- Build execution queue (topological sort)
    local visited = {}
    local function visit(block)
        if not block or visited[block.id] then return end
        visited[block.id] = true
        
        table.insert(self.executionQueue, block)
        
        for _, connection in ipairs(block.connections) do
            local nextBlock = VisualProgrammingInterface.manager:getBlock(connection.id)
            visit(nextBlock)
        end
    end
    
    -- Get blocks sorted by vertical position
    local sortedBlocks = {}
    for _, block in pairs(VisualProgrammingInterface.manager.blocks) do
        table.insert(sortedBlocks, block)
    end
    table.sort(sortedBlocks, function(a, b) return a.y < b.y end)
    
    -- Build execution queue starting from top blocks
    for _, block in ipairs(sortedBlocks) do
        visit(block)
    end
    
    -- Start execution timer
    self:continueExecution()
end

-- Continue execution after pause or between blocks
function VisualProgrammingInterface.Execution:continueExecution()
    if not self.isRunning or self.isPaused then return end
    
    if #self.executionQueue > 0 then
        local nextBlock = table.remove(self.executionQueue, 1)
        self:executeBlock(nextBlock)
        
        -- Schedule next block execution
        Interface.Timer(self.delay, function()
            self:continueExecution()
        end)
    else
        self:stop()
    end
end

-- Pause execution
function VisualProgrammingInterface.Execution:pause()
    if not self.isRunning then return end
    self.isPaused = true
    
    -- Visual feedback for paused state
    if self.currentBlock then
        local blockWindow = "Block" .. self.currentBlock.id
        if DoesWindowNameExist(blockWindow) then
            WindowSetTintColor(blockWindow, 255, 165, 0) -- Orange for paused
        end
    end
end

-- Resume execution
function VisualProgrammingInterface.Execution:resume()
    if not self.isRunning or not self.isPaused then return end
    self.isPaused = false
    self:continueExecution()
end

-- Stop execution
function VisualProgrammingInterface.Execution:stop()
    self.isRunning = false
    self.isPaused = false
    self.currentBlock = nil
    self.executionQueue = {}
    
    -- Reset visual states
    for id, _ in pairs(VisualProgrammingInterface.manager.blocks) do
        local blockWindow = "Block" .. id
        if DoesWindowNameExist(blockWindow) then
            WindowSetTintColor(blockWindow, 255, 255, 255) -- Reset to white
        end
    end
end

-- Get execution status
function VisualProgrammingInterface.Execution:getStatus()
    return {
        isRunning = self.isRunning,
        isPaused = self.isPaused,
        currentBlock = self.currentBlock and self.currentBlock.id or nil,
        remainingBlocks = #self.executionQueue,
        blockStates = self.blockStates
    }
end
