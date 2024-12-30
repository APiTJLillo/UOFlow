-- Main execution system entry point

-- Test flow functionality
function VisualProgrammingInterface.Execution:testFlow()
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
    for id, _ in pairs(VisualProgrammingInterface.manager.blocks) do
        self.blockStates[id] = VisualProgrammingInterface.Execution.BlockState.PENDING
    end
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
        if not block then
            Debug.Print("Warning: Attempted to visit nil block")
            return
        end
        if visited[block.id] then return end
        
        -- Verify block is properly tracked
        if not VisualProgrammingInterface.manager.blocks[block.id] then
            Debug.Print("Warning: Block " .. block.id .. " not tracked by manager")
            -- Add block to manager's tracking
            VisualProgrammingInterface.manager.blocks[block.id] = block
            Debug.Print("Added block " .. block.id .. " to manager tracking")
        end
        
        visited[block.id] = true
        table.insert(executionQueue, block)
        
        -- Check if connections exist
        if block.connections then
            for _, connection in ipairs(block.connections) do
                if connection and connection.id then
                    local nextBlock = VisualProgrammingInterface.manager:getBlock(connection.id)
                    if nextBlock then
                        visit(nextBlock)
                    else
                        Debug.Print("Warning: Connected block " .. connection.id .. " not found")
                    end
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

-- Test a single block
function VisualProgrammingInterface.Execution:testBlock(block)
    if not block then return end
    
    Debug.Print("Testing single block " .. block.id)
    
    -- Reset execution state
    self.blockStates = {}
    self.blockStates[block.id] = VisualProgrammingInterface.Execution.BlockState.PENDING
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

-- Initialize the execution system
VisualProgrammingInterface.Execution:initialize()
