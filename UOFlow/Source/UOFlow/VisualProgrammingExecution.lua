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
    
    -- Check if Actions system is properly initialized
    if not VisualProgrammingInterface.Actions or type(VisualProgrammingInterface.Actions.get) ~= "function" then
        Debug.Print("Error: Actions system not properly initialized")
        self.blockStates[block.id] = BlockState.ERROR
        if DoesWindowNameExist(blockWindow) then
            WindowSetTintColor(blockWindow, 255, 0, 0) -- Red for error
        end
        return false
    end

    -- Get action definition
    local success, action = pcall(function() return VisualProgrammingInterface.Actions:get(block.type) end)
    if not success or not action then
        self.blockStates[block.id] = BlockState.ERROR
        if DoesWindowNameExist(blockWindow) then
            WindowSetTintColor(blockWindow, 255, 0, 0) -- Red for error
        end
        Debug.Print("Unknown action type: " .. block.type)
        return false
    end
    
    -- Validate parameters
    if type(VisualProgrammingInterface.Actions.validateParams) ~= "function" then
        Debug.Print("Error: validateParams not available")
        self.blockStates[block.id] = BlockState.ERROR
        if DoesWindowNameExist(blockWindow) then
            WindowSetTintColor(blockWindow, 255, 0, 0) -- Red for error
        end
        return false
    end
    
    success, result = pcall(function() 
        return VisualProgrammingInterface.Actions:validateParams(block.type, block.params)
    end)
    
    if not success or not result then
        self.blockStates[block.id] = BlockState.ERROR
        if DoesWindowNameExist(blockWindow) then
            WindowSetTintColor(blockWindow, 255, 0, 0) -- Red for error
        end
        Debug.Print("Parameter validation failed: " .. tostring(result))
        return false
    end
    
    -- Execute action
    if type(VisualProgrammingInterface.Actions.execute) ~= "function" then
        Debug.Print("Error: execute not available")
        self.blockStates[block.id] = BlockState.ERROR
        if DoesWindowNameExist(blockWindow) then
            WindowSetTintColor(blockWindow, 255, 0, 0) -- Red for error
        end
        return false
    end
    
    success, result = pcall(function()
        return VisualProgrammingInterface.Actions:execute(block.type, block.params)
    end)
    
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
    
    -- Check if manager exists and is initialized
    if not VisualProgrammingInterface.manager then
        Debug.Print("Error: Manager not initialized")
        return false
    end
    
    -- Check if blocks exist
    if not VisualProgrammingInterface.manager.blocks then
        Debug.Print("Error: No blocks found")
        return false
    end
    
    -- Reset visual states
    local success, err = pcall(function()
        for id, _ in pairs(VisualProgrammingInterface.manager.blocks) do
            local blockWindow = "Block" .. id
            if DoesWindowNameExist(blockWindow) then
                WindowSetTintColor(blockWindow, 255, 255, 255) -- Reset to white
            end
            self.blockStates[id] = BlockState.PENDING
        end
    end)
    
    if not success then
        Debug.Print("Error resetting visual states: " .. tostring(err))
        return false
    end
    
    -- Build execution queue (topological sort)
    local visited = {}
    local function visit(block)
        if not block or visited[block.id] then return end
        visited[block.id] = true
        
        table.insert(self.executionQueue, block)
        
        -- Check if connections exist
        if block.connections then
            for _, connection in ipairs(block.connections) do
                if connection and connection.id then
                    local nextBlock = VisualProgrammingInterface.manager:getBlock(connection.id)
                    visit(nextBlock)
                end
            end
        end
    end
    
    -- Get blocks sorted by vertical position
    local sortedBlocks = {}
    success, err = pcall(function()
        for _, block in pairs(VisualProgrammingInterface.manager.blocks) do
            table.insert(sortedBlocks, block)
        end
        table.sort(sortedBlocks, function(a, b) 
            return (a and a.y or 0) < (b and b.y or 0)
        end)
    end)
    
    if not success then
        Debug.Print("Error sorting blocks: " .. tostring(err))
        return false
    end
    
    -- Build execution queue starting from top blocks
    for _, block in ipairs(sortedBlocks) do
        visit(block)
    end
    
    -- Start execution timer
    self:continueExecution()
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
    
    -- Check if manager exists and is initialized
    if not VisualProgrammingInterface.manager then
        Debug.Print("Warning: Manager not initialized during stop")
        return
    end
    
    -- Check if blocks exist
    if not VisualProgrammingInterface.manager.blocks then
        Debug.Print("Warning: No blocks found during stop")
        return
    end
    
    -- Reset visual states
    local success, err = pcall(function()
        for id, _ in pairs(VisualProgrammingInterface.manager.blocks) do
            local blockWindow = "Block" .. id
            if DoesWindowNameExist(blockWindow) then
                WindowSetTintColor(blockWindow, 255, 255, 255) -- Reset to white
            end
        end
    end)
    
    if not success then
        Debug.Print("Error resetting visual states during stop: " .. tostring(err))
    end
end

-- Timer variables
VisualProgrammingInterface.Execution.resetTimer = 0
VisualProgrammingInterface.Execution.continueTimer = 0

-- Update handler for timers
function VisualProgrammingInterface.Execution.OnUpdate(timePassed)
    if not VisualProgrammingInterface.Execution then return end
    
    -- Handle test block reset
    if VisualProgrammingInterface.Execution.resetBlockId then
        if not VisualProgrammingInterface.Execution.resetTimer then
            VisualProgrammingInterface.Execution.resetTimer = 0
        end
        
        VisualProgrammingInterface.Execution.resetTimer = VisualProgrammingInterface.Execution.resetTimer + timePassed
        if VisualProgrammingInterface.Execution.resetTimer >= 1 then -- 1 second delay
            local blockWindow = "Block" .. VisualProgrammingInterface.Execution.resetBlockId
            if DoesWindowNameExist(blockWindow) then
                WindowSetTintColor(blockWindow, 255, 255, 255) -- Reset to white
            end
            VisualProgrammingInterface.Execution.resetBlockId = nil
            VisualProgrammingInterface.Execution.resetTimer = 0
        end
    end
    
    -- Handle execution continuation
    if VisualProgrammingInterface.Execution.isRunning and not VisualProgrammingInterface.Execution.isPaused then
        if not VisualProgrammingInterface.Execution.continueTimer then
            VisualProgrammingInterface.Execution.continueTimer = 0
        end
        
        VisualProgrammingInterface.Execution.continueTimer = VisualProgrammingInterface.Execution.continueTimer + timePassed
        if VisualProgrammingInterface.Execution.continueTimer >= (VisualProgrammingInterface.Execution.delay / 1000) then
            VisualProgrammingInterface.Execution.continueTimer = 0
            if type(VisualProgrammingInterface.Execution.continueExecution) == "function" then
                VisualProgrammingInterface.Execution:continueExecution()
            else
                Debug.Print("Warning: continueExecution is not a function")
                -- Unregister the update handler since we can't continue
                UnregisterEventHandler("OnUpdate", "VisualProgrammingInterface.Execution.OnUpdate")
            end
        end
    end
end

-- Test a single block
function VisualProgrammingInterface.Execution:testBlock(block)
    if not block then return end
    
    -- Reset block state
    self.blockStates = {}
    self.blockStates[block.id] = BlockState.PENDING
    
    -- Execute the block
    self:executeBlock(block)
    
    -- Set up reset timer
    self.resetBlockId = block.id
    self.resetTimer = 0
end

-- Continue execution after pause or between blocks
function VisualProgrammingInterface.Execution:continueExecution()
    if not self.isRunning or self.isPaused then return end
    
    if #self.executionQueue > 0 then
        local nextBlock = table.remove(self.executionQueue, 1)
        self:executeBlock(nextBlock)
        
        -- Set up continue timer
        self.continueTimer = 0
    else
        self:stop()
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
