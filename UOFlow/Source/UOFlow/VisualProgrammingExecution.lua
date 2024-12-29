-- Execution engine for Visual Programming Interface

VisualProgrammingInterface.Execution = {
    isRunning = false,
    isPaused = false,
    currentBlock = nil,
    executionQueue = {},
    blockStates = {}, -- Stores execution state for each block
    delay = 1000, -- Default delay between blocks in ms
    waitingForTimer = false -- New flag to track timer state
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
    
    Debug.Print("Executing block " .. block.id .. " (" .. block.type .. ")")
    
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
    
    -- Set waiting flag before execution
    self.waitingForTimer = true
    
    Debug.Print("Executing action for block " .. block.id)
    success, result = pcall(function()
        return VisualProgrammingInterface.Actions:execute(block.type, block.params)
    end)
    
    -- If no timer was started or ActionTimer doesn't exist, clear the waiting flag
    if not VisualProgrammingInterface.ActionTimer or not VisualProgrammingInterface.ActionTimer.isWaiting then
        Debug.Print("No timer started for block " .. block.id)
        self.waitingForTimer = false
    else
        Debug.Print("Timer started for block " .. block.id)
        -- Ensure timer has valid state
        if not VisualProgrammingInterface.ActionTimer.currentQueueId then
            VisualProgrammingInterface.ActionTimer.currentQueueId = nil
        end
        if not VisualProgrammingInterface.ActionTimer.functionQueue then
            VisualProgrammingInterface.ActionTimer.functionQueue = {}
        end
    end
    
    -- Update block state based on execution result
    if success then
        if not self.waitingForTimer then
            Debug.Print("Block " .. block.id .. " completed immediately")
            self.blockStates[block.id] = BlockState.COMPLETED
            if DoesWindowNameExist(blockWindow) then
                WindowSetTintColor(blockWindow, 0, 255, 0) -- Green for success
            end
            
            -- Ensure any lingering timers are cleared
            if VisualProgrammingInterface.ActionTimer then
                VisualProgrammingInterface.ActionTimer.isWaiting = false
                VisualProgrammingInterface.ActionTimer.callback = nil
                VisualProgrammingInterface.ActionTimer.functionQueue = {}
                VisualProgrammingInterface.ActionTimer.currentQueueId = nil
                VisualProgrammingInterface.ActionTimer.isComplete = false
            end
        end
        -- Note: If waiting for timer, the state will be updated when timer completes
    else
        Debug.Print("Block " .. block.id .. " failed: " .. tostring(result))
        self.blockStates[block.id] = BlockState.ERROR
        if DoesWindowNameExist(blockWindow) then
            WindowSetTintColor(blockWindow, 255, 0, 0) -- Red for error
        end
        
        -- Clear any pending timers
        if VisualProgrammingInterface.ActionTimer then
            VisualProgrammingInterface.ActionTimer.isWaiting = false
            VisualProgrammingInterface.ActionTimer.callback = nil
            VisualProgrammingInterface.ActionTimer.functionQueue = {}
            VisualProgrammingInterface.ActionTimer.currentQueueId = nil
            VisualProgrammingInterface.ActionTimer.isComplete = false
        end
        
        -- Set up cleanup timer
        self:queueBlocksForReset()
        self.waitingForTimer = false
        
        -- Stop execution on error
        Debug.Print("Stopping execution due to block failure")
        self:stop()
        -- Log detailed error information
        local errorInfo = {
            blockId = block.id,
            blockType = block.type,
            params = block.params,
            error = result -- pcall returns error message as second value on failure
        }
        Debug.Print("Block execution error: " .. tostring(result))
        Debug.Print("Error details: " .. table.concat({
            "Block ID: " .. tostring(errorInfo.blockId),
            "Block Type: " .. tostring(errorInfo.blockType),
            "Parameters: " .. table.concat(
                (function()
                    local params = {}
                    for k,v in pairs(errorInfo.params or {}) do
                        table.insert(params, k .. "=" .. tostring(v))
                    end
                    return params
                end)(),
                ", "
            )
        }, "\n  "))
    end
    
    return success
end

-- Start execution of the block sequence
function VisualProgrammingInterface.Execution:start()
    if self.isRunning then return end
    
    -- Reset execution state
    self.isRunning = true
    self.isPaused = false
    self.blockStates = {}
    self.executionQueue = {}
    self.waitingForTimer = false
    
    -- Clear any existing timers
    if VisualProgrammingInterface.ActionTimer then
        Debug.Print("Clearing existing timers before start")
        VisualProgrammingInterface.ActionTimer.isWaiting = false
        VisualProgrammingInterface.ActionTimer.callback = nil
        VisualProgrammingInterface.ActionTimer.functionQueue = {}
        VisualProgrammingInterface.ActionTimer.currentQueueId = nil
        VisualProgrammingInterface.ActionTimer.isComplete = false
    end
    
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
    
    Debug.Print("Resuming execution")
    self.isPaused = false
    
    -- Reset timer states
    self.continueTimer = 0
    
    -- Check if we should be waiting for a timer
    if not VisualProgrammingInterface.ActionTimer or not VisualProgrammingInterface.ActionTimer.isWaiting then
        Debug.Print("No active timer found during resume")
        self.waitingForTimer = false
    end
    
    -- Set up continue timer if not waiting for action timer
    if not self.waitingForTimer then
        Debug.Print("Setting up continue timer for resume")
        self.continueTimer = 0
    end
    
    self:continueExecution()
end

-- Stop execution
function VisualProgrammingInterface.Execution:stop()
    Debug.Print("Stopping execution")
    
    -- If we're waiting for a timer, cancel it
    if self.waitingForTimer and VisualProgrammingInterface.ActionTimer then
        Debug.Print("Canceling active timer")
        VisualProgrammingInterface.ActionTimer.isWaiting = false
        VisualProgrammingInterface.ActionTimer.callback = nil
        VisualProgrammingInterface.ActionTimer.functionQueue = {}
        VisualProgrammingInterface.ActionTimer.currentQueueId = nil
        VisualProgrammingInterface.ActionTimer.isComplete = false
    end
    
    -- Reset all execution state
    self.isRunning = false
    self.isPaused = false
    self.currentBlock = nil
    self.executionQueue = {}
    self.waitingForTimer = false
    self.blockStates = {}
    
    -- Reset the ActionTimer system
    if VisualProgrammingInterface.ActionTimer then
        Debug.Print("Resetting ActionTimer system")
        VisualProgrammingInterface.ActionTimer.isWaiting = false
        VisualProgrammingInterface.ActionTimer.callback = nil
        VisualProgrammingInterface.ActionTimer.functionQueue = {}
        VisualProgrammingInterface.ActionTimer.currentQueueId = nil
        VisualProgrammingInterface.ActionTimer.isComplete = false
        VisualProgrammingInterface.ActionTimer.currentTime = 0
        VisualProgrammingInterface.ActionTimer.targetTime = 0
    end
    
    -- Set up reset timer for all blocks with a delay
    self:queueBlocksForReset()
    self.continueTimer = 0
    self.resetBlockId = nil
    
    Debug.Print("Execution system fully reset")
end

-- Timer variables
VisualProgrammingInterface.Execution.resetTimer = 0
VisualProgrammingInterface.Execution.continueTimer = 0
VisualProgrammingInterface.Execution.resetBlockIds = {} -- Track multiple blocks for resetting
VisualProgrammingInterface.Execution.resetDelay = 1500 -- Delay before resetting blocks (ms)

-- Update handler for timers
function VisualProgrammingInterface.Execution.OnUpdate(timePassed)
    if not VisualProgrammingInterface.Execution then return end
    
    -- Handle block reset timers
    if VisualProgrammingInterface.Execution.resetBlockId or 
    (VisualProgrammingInterface.Execution.resetBlockIds and #VisualProgrammingInterface.Execution.resetBlockIds > 0) then
        --Debug.Print("Reset timer active - Current time: " .. VisualProgrammingInterface.Execution.resetTimer)
        
        -- Initialize timer if needed
        if not VisualProgrammingInterface.Execution.resetTimer then
            VisualProgrammingInterface.Execution.resetTimer = 0
            Debug.Print("Initialized reset timer")
        end
        
        -- Update timer
        VisualProgrammingInterface.Execution.resetTimer = VisualProgrammingInterface.Execution.resetTimer + timePassed
        --Debug.Print("Reset timer updated: " .. VisualProgrammingInterface.Execution.resetTimer)
        
        if VisualProgrammingInterface.Execution.resetTimer >= (VisualProgrammingInterface.Execution.resetDelay / 1000) then
            Debug.Print("Reset timer complete - resetting block visuals")
            -- Reset blocks to default state
            if VisualProgrammingInterface.Execution.resetBlockId then
                local blockWindow = "Block" .. VisualProgrammingInterface.Execution.resetBlockId
                if DoesWindowNameExist(blockWindow) then
                    Debug.Print("Resetting single block " .. VisualProgrammingInterface.Execution.resetBlockId)
                    WindowSetTintColor(blockWindow, 255, 255, 255)
                end
                VisualProgrammingInterface.Execution.resetBlockId = nil
            end
            
            if VisualProgrammingInterface.Execution.resetBlockIds then
                for _, id in ipairs(VisualProgrammingInterface.Execution.resetBlockIds) do
                    local blockWindow = "Block" .. id
                    if DoesWindowNameExist(blockWindow) then
                        Debug.Print("Resetting block " .. id)
                        WindowSetTintColor(blockWindow, 255, 255, 255)
                    end
                end
                VisualProgrammingInterface.Execution.resetBlockIds = {}
            end
            
            -- Clear reset state
            Debug.Print("Clearing reset timer state")
            VisualProgrammingInterface.Execution.waitingForTimer = false
            VisualProgrammingInterface.Execution.resetTimer = 0
        end
    end
    
    -- Handle execution continuation
    if VisualProgrammingInterface.Execution.isRunning and not VisualProgrammingInterface.Execution.isPaused then
        if not VisualProgrammingInterface.Execution.waitingForTimer then
            if not VisualProgrammingInterface.Execution.continueTimer then
                VisualProgrammingInterface.Execution.continueTimer = 0
            end
            
            VisualProgrammingInterface.Execution.continueTimer = VisualProgrammingInterface.Execution.continueTimer + timePassed
            if VisualProgrammingInterface.Execution.continueTimer >= (VisualProgrammingInterface.Execution.delay / 1000) then
                VisualProgrammingInterface.Execution.continueTimer = 0
                if type(VisualProgrammingInterface.Execution.continueExecution) == "function" then
                    Debug.Print("Continuing execution after delay")
                    VisualProgrammingInterface.Execution:continueExecution()
                end
            end
        end
    end
end

-- Initialize execution system
function VisualProgrammingInterface.Execution:initialize()
    -- Register as a completion callback with the ActionTimer
    VisualProgrammingInterface.ActionTimer:registerCompletionCallback(
        "execution",
        function()
            if VisualProgrammingInterface.Execution.signalTimerComplete then
                VisualProgrammingInterface.Execution:signalTimerComplete()
            end
        end
    )
    
    -- Initialize timer variables
    VisualProgrammingInterface.Execution.resetTimer = 0
    VisualProgrammingInterface.Execution.continueTimer = 0
    VisualProgrammingInterface.Execution.resetBlockIds = {}
    VisualProgrammingInterface.Execution.resetDelay = 1500 -- Delay before resetting blocks (ms)
end

-- Test a single block
function VisualProgrammingInterface.Execution:testBlock(block)
    if not block then return end
    
    Debug.Print("Testing single block " .. block.id)
    
    -- Reset execution state
    self.blockStates = {}
    self.blockStates[block.id] = BlockState.PENDING
    self.waitingForTimer = false
    
    -- Clear any existing timers
    if VisualProgrammingInterface.ActionTimer then
        Debug.Print("Clearing existing timers before test")
        VisualProgrammingInterface.ActionTimer.isWaiting = false
        VisualProgrammingInterface.ActionTimer.callback = nil
        VisualProgrammingInterface.ActionTimer.functionQueue = {}
        VisualProgrammingInterface.ActionTimer.currentQueueId = nil
        VisualProgrammingInterface.ActionTimer.isComplete = false
    end
    
    -- Execute the block and capture result
    local success = self:executeBlock(block)
    
    -- Set up reset timer for this block
    Debug.Print("Setting up reset timer for block " .. block.id)
    self.resetBlockId = block.id
    self.resetTimer = 0
    self.continueTimer = 0
    
    return success
end

-- Test an entire flow
function VisualProgrammingInterface.Execution:testFlow()
    -- if self.isRunning then 
    --     Debug.Print("Cannot start flow test - flow is already running")
    --     return false, "Flow is already running" 
    -- end
    
    -- Stop any existing execution and reset state
    self:stop()
    
    Debug.Print("Starting flow test")
    
    -- Initialize test results
    local testResults = {
        blocks = {},
        success = true,
        executionOrder = {}
    }
    
    -- Reset execution state
    self.blockStates = {}
    self.waitingForTimer = false
    self.isRunning = true -- Set running state to true for proper timer handling
    
    -- Clear any existing timers
    if VisualProgrammingInterface.ActionTimer then
        Debug.Print("Clearing existing timers before flow test")
        VisualProgrammingInterface.ActionTimer.isWaiting = false
        VisualProgrammingInterface.ActionTimer.callback = nil
        VisualProgrammingInterface.ActionTimer.functionQueue = {}
        VisualProgrammingInterface.ActionTimer.currentQueueId = nil
        VisualProgrammingInterface.ActionTimer.isComplete = false
    end
    
    -- Check if manager exists and is initialized
    if not VisualProgrammingInterface.manager then
        self.isRunning = false
        return false, "Manager not initialized"
    end
    
    -- Check if blocks exist
    if not VisualProgrammingInterface.manager.blocks then
        self.isRunning = false
        return false, "No blocks found"
    end
    
    -- Build execution queue (topological sort)
    local executionQueue = {}
    local visited = {}
    local function visit(block)
        if not block or visited[block.id] then return end
        visited[block.id] = true
        
        table.insert(executionQueue, block)
        
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
    for _, block in pairs(VisualProgrammingInterface.manager.blocks) do
        table.insert(sortedBlocks, block)
    end
    table.sort(sortedBlocks, function(a, b) 
        return (a and a.y or 0) < (b and b.y or 0)
    end)
    
    -- Build execution queue starting from top blocks
    for _, block in ipairs(sortedBlocks) do
        visit(block)
    end
    
    Debug.Print("Built execution queue with " .. #executionQueue .. " blocks")
    
    -- Store execution queue for processing in OnUpdate
    self.executionQueue = executionQueue
    
    -- Execute first block
    if #self.executionQueue > 0 then
        local firstBlock = table.remove(self.executionQueue, 1)
        table.insert(testResults.executionOrder, firstBlock.id)
        
        Debug.Print("Executing first block " .. firstBlock.id)
        local success = self:executeBlock(firstBlock)
        testResults.blocks[firstBlock.id] = {
            type = firstBlock.type,
            params = firstBlock.params,
            success = success,
            state = self.blockStates[firstBlock.id]
        }
        
        if not success then
            testResults.success = false
            testResults.error = "Failed at block " .. firstBlock.id
            
            -- Clear any pending timers
            if VisualProgrammingInterface.ActionTimer then
                Debug.Print("Clearing timers after block failure")
                VisualProgrammingInterface.ActionTimer.isWaiting = false
                VisualProgrammingInterface.ActionTimer.callback = nil
                VisualProgrammingInterface.ActionTimer.functionQueue = {}
                VisualProgrammingInterface.ActionTimer.currentQueueId = nil
                VisualProgrammingInterface.ActionTimer.isComplete = false
            end
            
            -- Set up reset timer for all blocks
            self:queueBlocksForReset()
            self.waitingForTimer = false
            self.isRunning = false
            
            return true, testResults
        end
    end
    
    -- Return initial results, remaining blocks will be processed via OnUpdate
    return true, testResults
end

-- Continue execution after pause or between blocks
function VisualProgrammingInterface.Execution:continueExecution()
    if not self.isRunning or self.isPaused then
        Debug.Print("Cannot continue execution: " .. 
            (not self.isRunning and "not running" or
             self.isPaused and "paused" or
             "unknown reason"))
        return
    end
    
    -- If we're waiting for a timer, don't start the next block yet
    if self.waitingForTimer then
        Debug.Print("Waiting for timer to complete before continuing")
        return
    end
    
    if #self.executionQueue > 0 then
        local nextBlock = table.remove(self.executionQueue, 1)
        Debug.Print("Continuing with next block " .. nextBlock.id)
        
        -- Ensure previous block is marked as completed
        if self.currentBlock then
            self.blockStates[self.currentBlock.id] = BlockState.COMPLETED
            local blockWindow = "Block" .. self.currentBlock.id
            if DoesWindowNameExist(blockWindow) then
                WindowSetTintColor(blockWindow, 0, 255, 0) -- Green for success
            end
        end
        
        -- Execute next block
        self:executeBlock(nextBlock)
        
        -- Set up continue timer if not waiting for action timer
        if not self.waitingForTimer then
            Debug.Print("Setting up continue timer")
            self.continueTimer = 0
        end
    else
        Debug.Print("No more blocks to execute")
        -- Don't stop immediately, let the current block finish
        if not self.waitingForTimer then
            self:stop()
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
        blockStates = self.blockStates,
        waitingForTimer = self.waitingForTimer
    }
end

-- Signal completion of a timer-based action
function VisualProgrammingInterface.Execution:signalTimerComplete()
    if not self.currentBlock then 
        Debug.Print("Timer complete but no current block")
        return 
    end
    
    Debug.Print("Timer complete for block " .. self.currentBlock.id)
    
    -- Update block state to completed
    self.blockStates[self.currentBlock.id] = BlockState.COMPLETED
    local blockWindow = "Block" .. self.currentBlock.id
    if DoesWindowNameExist(blockWindow) then
        Debug.Print("Setting block " .. self.currentBlock.id .. " visual state to completed")
        WindowSetTintColor(blockWindow, 0, 255, 0) -- Green for success
    end
    
    -- Clear waiting flag and ensure ActionTimer is properly reset
    Debug.Print("Resetting timer state")
    self.waitingForTimer = false
    if VisualProgrammingInterface.ActionTimer then
        VisualProgrammingInterface.ActionTimer.isWaiting = false
        VisualProgrammingInterface.ActionTimer.callback = nil
        VisualProgrammingInterface.ActionTimer.functionQueue = {}
        VisualProgrammingInterface.ActionTimer.currentQueueId = nil
        VisualProgrammingInterface.ActionTimer.isComplete = false
    end
    
    -- If this was the last block, clean up and stop
    if #self.executionQueue == 0 then
        Debug.Print("Last block completed, cleaning up")
        
        -- Clear any pending timers
        if VisualProgrammingInterface.ActionTimer then
            Debug.Print("Clearing final timers")
            VisualProgrammingInterface.ActionTimer.isWaiting = false
            VisualProgrammingInterface.ActionTimer.callback = nil
            VisualProgrammingInterface.ActionTimer.functionQueue = {}
            VisualProgrammingInterface.ActionTimer.currentQueueId = nil
            VisualProgrammingInterface.ActionTimer.isComplete = false
        end
        
        -- Keep the final state visible for a moment before resetting
        Debug.Print("Setting up delayed reset")
        self.resetTimer = 0
        self:queueBlocksForReset()
        
        -- Keep execution state until reset is complete
        self.waitingForTimer = false
        
        -- Call stop after a delay to allow final state to be visible
        self:stop()
        
        Debug.Print("Flow execution complete")
        return
    end
    
    -- Continue execution with next block
    Debug.Print("Continuing execution with " .. #self.executionQueue .. " blocks remaining")
    self:continueExecution()
end

function VisualProgrammingInterface.Execution:queueBlocksForReset()
    Debug.Print("Queueing blocks for reset")
    VisualProgrammingInterface.Execution.resetBlockIds = {}
    -- Queue all blocks for reset
    for id, _ in pairs(VisualProgrammingInterface.manager.blocks) do
        Debug.Print("- Queueing block " .. id)
        table.insert(VisualProgrammingInterface.Execution.resetBlockIds, id)
    end
    -- Reset timer for delayed reset
    VisualProgrammingInterface.Execution.resetTimer = 0
    Debug.Print("Reset queue initialized with " .. #VisualProgrammingInterface.Execution.resetBlockIds .. " blocks")
end
