-- Flow control and execution management
function VisualProgrammingInterface.Execution:hardResetForTestRun()
    if UOWNativeLog then
        UOWNativeLog("[VPExec] hard reset for test")
    end
    Debug.Print("Hard resetting execution state for flow test")

    self.isRunning = false
    self.isPaused = false
    self.currentBlock = nil
    self.executionQueue = {}
    self.waitingForTimer = false
    self.blockStates = {}
    self.continueTimer = 0
    self.resetTimer = 0
    self.resetBlockId = nil
    self.resetBlockIds = {}

    if VisualProgrammingInterface.ActionTimer then
        VisualProgrammingInterface.ActionTimer.isWaiting = false
        VisualProgrammingInterface.ActionTimer.callback = nil
        VisualProgrammingInterface.ActionTimer.functionQueue = {}
        VisualProgrammingInterface.ActionTimer.currentQueueId = nil
        VisualProgrammingInterface.ActionTimer.isComplete = false
        VisualProgrammingInterface.ActionTimer.currentTime = 0
        VisualProgrammingInterface.ActionTimer.targetTime = 0
    end

    if VisualProgrammingInterface.manager and type(VisualProgrammingInterface.manager.blocks) == "table" then
        for id, block in pairs(VisualProgrammingInterface.manager.blocks) do
            if type(block) == "table" and block.id ~= nil then
                local blockWindow = "Block" .. id
                if DoesWindowNameExist(blockWindow) then
                    WindowSetTintColor(blockWindow, 255, 255, 255)
                end
            end
        end
    end
end

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
    for id, _ in pairs(VisualProgrammingInterface.manager.blocks) do
        local blockWindow = "Block" .. id
        if DoesWindowNameExist(blockWindow) then
            WindowSetTintColor(blockWindow, 255, 255, 255) -- Reset to white
        end
        self.blockStates[id] = VisualProgrammingInterface.Execution.BlockState.PENDING
    end
    
    -- Build execution queue in order of connections
    local visited = {}
    local function visit(block)
        if not block or type(block) ~= "table" or block.id == nil then
            return
        end
        if visited[block.id] then return end
        
        -- Add current block to queue
        table.insert(self.executionQueue, block)
        visited[block.id] = true
        Debug.Print("Added block " .. block.id .. " to execution queue")
        
        -- Visit next block in chain if it exists
        if block.connections and #block.connections > 0 then
            local nextBlockId = block.connections[1].id
            local nextBlock = VisualProgrammingInterface.manager:getBlock(nextBlockId)
            if nextBlock then
                Debug.Print("Following connection from block " .. block.id .. " to block " .. nextBlockId)
                visit(nextBlock)
            end
        end
    end
    
    -- Find the first block (one with no incoming connections)
    local firstBlock = nil
    for _, block in pairs(VisualProgrammingInterface.manager.blocks) do
        if type(block) == "table" and block.id ~= nil then
            local hasIncoming = false
            for _, otherBlock in pairs(VisualProgrammingInterface.manager.blocks) do
                if type(otherBlock) == "table" and otherBlock.connections then
                    for _, conn in ipairs(otherBlock.connections) do
                        if conn.id == block.id then
                            hasIncoming = true
                            break
                        end
                    end
                end
                if hasIncoming then break end
            end
            if not hasIncoming then
                firstBlock = block
                break
            end
        end
    end
    
    -- Start building queue from the first block
    if firstBlock then
        Debug.Print("Starting execution queue with block " .. firstBlock.id)
        visit(firstBlock)
    else
        Debug.Print("Error: Could not find starting block")
        return false
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
    
    -- Set up reset timer for all blocks with a delay
    self:queueBlocksForReset()
    self.continueTimer = 0
    self.resetBlockId = nil
    
    -- Wait for reset timer to complete before clearing execution state
    if not self.waitingForTimer then
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
    end
    
    Debug.Print("Execution system fully reset")
end

-- Continue execution after pause or between blocks
function VisualProgrammingInterface.Execution:continueExecution()
    if not self.isRunning or self.isPaused then
        if UOWNativeLog then
            UOWNativeLog("[VPExec] continue blocked", "running=" .. tostring(self.isRunning), "paused=" .. tostring(self.isPaused))
        end
        Debug.Print("Cannot continue execution: " .. 
            (not self.isRunning and "not running" or
             self.isPaused and "paused" or
             "unknown reason"))
        return
    end
    
    -- If we're waiting for a timer, don't start the next block yet
    if self.waitingForTimer then
        if UOWNativeLog then
            UOWNativeLog("[VPExec] continue waiting", "queue=" .. tostring(#self.executionQueue), "currentBlock=" .. tostring(self.currentBlock and self.currentBlock.id))
        end
        Debug.Print("Waiting for timer to complete before continuing")
        return
    end
    
    if #self.executionQueue > 0 then
        local nextBlock = table.remove(self.executionQueue, 1)
        if UOWNativeLog then
            UOWNativeLog("[VPExec] continue nextBlock", tostring(nextBlock.id), tostring(nextBlock.type), "remaining=" .. tostring(#self.executionQueue))
        end
        Debug.Print("Continuing with next block " .. nextBlock.id)
        
        -- Mark previous block as completed and set to green
        if self.currentBlock then
            self.blockStates[self.currentBlock.id] = VisualProgrammingInterface.Execution.BlockState.COMPLETED
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
        if UOWNativeLog then
            UOWNativeLog("[VPExec] continue no more blocks", "current=" .. tostring(self.currentBlock and self.currentBlock.id))
        end
        Debug.Print("No more blocks to execute")
        -- Mark final block as completed and green before stopping
        if self.currentBlock then
            self.blockStates[self.currentBlock.id] = VisualProgrammingInterface.Execution.BlockState.COMPLETED
            local blockWindow = "Block" .. self.currentBlock.id
            if DoesWindowNameExist(blockWindow) then
                WindowSetTintColor(blockWindow, 0, 255, 0) -- Green for success
            end
        end
        -- Don't stop immediately, let the current block finish
        if not self.waitingForTimer then
            self:stop()
        end
    end
end
