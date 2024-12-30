-- Timer handling and execution timing
VisualProgrammingInterface.Execution.resetTimer = 0
VisualProgrammingInterface.Execution.continueTimer = 0
VisualProgrammingInterface.Execution.resetBlockIds = {} -- Track multiple blocks for resetting
VisualProgrammingInterface.Execution.resetDelay = 2000 -- Increased delay before resetting blocks (ms)

-- Update handler for timers
function VisualProgrammingInterface.Execution.OnUpdate(self, timePassed)
    if not VisualProgrammingInterface.Execution then return end
    
    -- Ensure timePassed is a number
    if type(timePassed) == "table" then
        timePassed = timePassed[1]
    end
    
    -- Handle block reset timers
    if VisualProgrammingInterface.Execution.resetBlockId or 
    (VisualProgrammingInterface.Execution.resetBlockIds and #VisualProgrammingInterface.Execution.resetBlockIds > 0) then
        -- Initialize timer if needed
        if not VisualProgrammingInterface.Execution.resetTimer then
            VisualProgrammingInterface.Execution.resetTimer = 0
            Debug.Print("Initialized reset timer")
        end
        
        -- Update timer
        VisualProgrammingInterface.Execution.resetTimer = VisualProgrammingInterface.Execution.resetTimer + timePassed
        
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
            
            -- Now that reset is complete, clear execution state if we're stopping
            if not VisualProgrammingInterface.Execution.isRunning then
                VisualProgrammingInterface.Execution.blockStates = {}
                VisualProgrammingInterface.Execution.currentBlock = nil
                VisualProgrammingInterface.Execution.executionQueue = {}
            end
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

-- Signal completion of a timer-based action
function VisualProgrammingInterface.Execution:signalTimerComplete()
    if not self.currentBlock then 
        Debug.Print("Timer complete but no current block")
        return 
    end
    
    Debug.Print("Timer complete for block " .. self.currentBlock.id)
    
    -- Update block state to completed
    self.blockStates[self.currentBlock.id] = VisualProgrammingInterface.Execution.BlockState.COMPLETED
    local blockWindow = "Block" .. self.currentBlock.id
    if DoesWindowNameExist(blockWindow) then
        Debug.Print("Setting block " .. self.currentBlock.id .. " visual state to completed")
        WindowSetTintColor(blockWindow, 0, 255, 0) -- Green for success
    end
    
    -- Clear waiting flag and ensure ActionTimer is properly reset
    Debug.Print("Resetting timer state")
    self.waitingForTimer = false
    if VisualProgrammingInterface.ActionTimer then
        Debug.Print("Resetting ActionTimer state")
        VisualProgrammingInterface.ActionTimer.isWaiting = false
        VisualProgrammingInterface.ActionTimer.callback = nil
        VisualProgrammingInterface.ActionTimer.functionQueue = {}
        VisualProgrammingInterface.ActionTimer.currentQueueId = nil
        VisualProgrammingInterface.ActionTimer.isComplete = false
    end
    
    -- Reset continue timer to ensure proper timing between blocks
    self.continueTimer = 0
    
    -- If this was the last block, clean up and stop
    if #self.executionQueue == 0 then
        Debug.Print("Last block completed, cleaning up")
        
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
    
    -- Continue execution with next block immediately
    Debug.Print("Continuing execution with " .. #self.executionQueue .. " blocks remaining")
    self:continueExecution()
end
