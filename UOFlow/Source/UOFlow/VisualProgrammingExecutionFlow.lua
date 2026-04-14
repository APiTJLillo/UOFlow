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
    self.primingFirstBlock = false
    self.blockStates = {}
    self.continueTimer = 0
    self.resetTimer = 0
    self.resetBlockId = nil
    self.resetBlockIds = {}
    self.pendingRawDispatch = nil
    self.pendingCompletionWatch = nil
    self.lastExecutedBlockId = nil

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
    
    local snapshotByKey, orderedRecords = nil, nil
    if type(self.buildExecutionSnapshot) == "function" then
        snapshotByKey, orderedRecords = self:buildExecutionSnapshot()
    end
    if snapshotByKey and type(self.buildExecutionQueueFromSnapshot) == "function" then
        self.executionQueue = {}
        self:buildExecutionQueueFromSnapshot(snapshotByKey, orderedRecords, self.executionQueue)
    end
    if #self.executionQueue == 0 then
        Debug.Print("Error: Could not build execution queue")
        return false
    end

    Debug.Print("Starting execution queue with block " .. tostring(self.executionQueue[1] and self.executionQueue[1].id))
    
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
    self.primingFirstBlock = false
    
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
        self.primingFirstBlock = false
        self.blockStates = {}
        self.pendingRawDispatch = nil
        self.pendingCompletionWatch = nil
        self.lastExecutedBlockId = nil
        
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
    local currentBlock = self.currentBlock
    local currentId = nil
    if type(currentBlock) == "table" then
        currentId = currentBlock.id
    elseif currentBlock ~= nil then
        currentId = currentBlock
    end

    if self.primingFirstBlock then
        if UOWNativeLog then
            UOWNativeLog("[VPExec] continue priming", "queue=" .. tostring(#self.executionQueue))
        end
        return
    end

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
            UOWNativeLog("[VPExec] continue waiting", "queue=" .. tostring(#self.executionQueue), "currentBlock=" .. tostring(currentId))
        end
        Debug.Print("Waiting for timer to complete before continuing")
        return
    end
    
    if #self.executionQueue > 0 then
        local nextBlock = self.executionQueue[1]

        -- Previous block completion/tinting is handled in signalTimerComplete().
        -- Keep the handoff minimal here so we can reliably enter the next block.
        local executeFn = self.executeBlock or VisualProgrammingInterface.Execution.executeBlock
        if type(executeFn) ~= "function" then
            return
        end

        self.silentTransition = true
        executeFn(self, nextBlock)
        self.silentTransition = false
        
        -- Set up continue timer if not waiting for action timer
        if not self.waitingForTimer then
            Debug.Print("Setting up continue timer")
            self.continueTimer = 0
        end
    else
        if UOWNativeLog then
            UOWNativeLog("[VPExec] continue no more blocks", "current=" .. tostring(currentId))
        end
        Debug.Print("No more blocks to execute")
        -- Mark final block as completed and green before stopping
        if currentId ~= nil then
            self.blockStates[currentId] = VisualProgrammingInterface.Execution.BlockState.COMPLETED
            local blockWindow = "Block" .. currentId
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
