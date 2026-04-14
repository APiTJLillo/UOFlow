-- Timer handling and execution timing
VisualProgrammingInterface.Execution.resetTimer = 0
VisualProgrammingInterface.Execution.continueTimer = 0
VisualProgrammingInterface.Execution.resetBlockIds = {} -- Track multiple blocks for resetting
VisualProgrammingInterface.Execution.resetDelay = 2000 -- Increased delay before resetting blocks (ms)

local function VPExecGetLoginTimeMs()
    if type(Interface) == "table" and type(Interface.TimeSinceLogin) == "number" then
        return Interface.TimeSinceLogin
    end
    return nil
end

-- Update handler for timers
function VisualProgrammingInterface.Execution.OnUpdate(self, timePassed)
    if not VisualProgrammingInterface.Execution then return end
    
    -- Ensure timePassed is a number
    if type(timePassed) == "table" then
        timePassed = timePassed[1]
    end

    local pendingRaw = VisualProgrammingInterface.Execution.pendingRawDispatch
    if type(pendingRaw) == "table" then
        if pendingRaw.stage == "queue" then
            if UOWNativeLog then
                UOWNativeLog("[VPExec] pending raw queue",
                    "helper=" .. tostring(pendingRaw.helper),
                    "spell=" .. tostring(pendingRaw.spellId),
                    "targetId=" .. tostring(pendingRaw.targetId),
                    "block=" .. tostring(pendingRaw.blockId))
            end
            pendingRaw.stage = "pump"
            if pendingRaw.helper == "UOWCastSpellOnIdRaw" and type(UOWCastSpellOnIdRaw) == "function" then
                UOWCastSpellOnIdRaw(pendingRaw.spellId, pendingRaw.targetId)
            elseif pendingRaw.helper == "UOWCastSpellRaw" and type(UOWCastSpellRaw) == "function" then
                UOWCastSpellRaw(pendingRaw.spellId)
            else
                pendingRaw.stage = "done"
            end
            return
        elseif pendingRaw.stage == "pump" then
            pendingRaw.pumpAttempts = (pendingRaw.pumpAttempts or 0) + 1
            pendingRaw.stage = "done"
            if UOWNativeLog then
                UOWNativeLog("[VPExec] pending raw pump",
                    "attempt=" .. tostring(pendingRaw.pumpAttempts),
                    "helper=" .. tostring(pendingRaw.helper),
                    "spell=" .. tostring(pendingRaw.spellId),
                    "targetId=" .. tostring(pendingRaw.targetId),
                    "next=done")
            end
            if type(UOWPumpQueuedRawCasts) == "function" then
                UOWPumpQueuedRawCasts()
            end
            return
        elseif pendingRaw.stage == "done" then
            if UOWNativeLog then
                UOWNativeLog("[VPExec] pending raw done",
                    "helper=" .. tostring(pendingRaw.helper),
                    "spell=" .. tostring(pendingRaw.spellId),
                    "targetId=" .. tostring(pendingRaw.targetId))
            end
            VisualProgrammingInterface.Execution.pendingRawDispatch = nil
        end
    end

    local completionWatch = VisualProgrammingInterface.Execution.pendingCompletionWatch
    if type(completionWatch) == "table" then
        local nowMs = VPExecGetLoginTimeMs()
        if type(nowMs) == "number" and nowMs >= (tonumber(completionWatch.dueAtMs) or 0) then
            local activeBlock = VisualProgrammingInterface.Execution.currentBlock
            local activeBlockId = type(activeBlock) == "table" and activeBlock.id or VisualProgrammingInterface.Execution.lastExecutedBlockId
            if UOWNativeLog then
                UOWNativeLog("[VPExec] completion watch fired",
                    "block=" .. tostring(completionWatch.blockId),
                    "active=" .. tostring(activeBlockId),
                    "spell=" .. tostring(completionWatch.spellId),
                    "dueAtMs=" .. tostring(completionWatch.dueAtMs),
                    "nowMs=" .. tostring(nowMs),
                    "waiting=" .. tostring(VisualProgrammingInterface.Execution.waitingForTimer))
            end

            VisualProgrammingInterface.Execution.pendingCompletionWatch = nil

            if VisualProgrammingInterface.Execution.waitingForTimer
            and type(VisualProgrammingInterface.Execution.signalTimerComplete) == "function" then
                VisualProgrammingInterface.Execution:signalTimerComplete()
                return
            end
        end
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
        if UOWNativeLog then
            UOWNativeLog("[VPExec] reset ticking",
                "timer=" .. tostring(VisualProgrammingInterface.Execution.resetTimer),
                "targets=" .. tostring(#(VisualProgrammingInterface.Execution.resetBlockIds or {})),
                "running=" .. tostring(VisualProgrammingInterface.Execution.isRunning))
        end
        
        if VisualProgrammingInterface.Execution.resetTimer >= (VisualProgrammingInterface.Execution.resetDelay / 1000) then
            if UOWNativeLog then
                UOWNativeLog("[VPExec] reset firing",
                    "targets=" .. tostring(#(VisualProgrammingInterface.Execution.resetBlockIds or {})),
                    "single=" .. tostring(VisualProgrammingInterface.Execution.resetBlockId))
            end
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
                        if UOWNativeLog then
                            UOWNativeLog("[VPExec] reset block", tostring(id))
                        end
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
                VisualProgrammingInterface.Execution.lastExecutedBlockId = nil
                VisualProgrammingInterface.Execution.pendingCompletionWatch = nil
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
    local currentBlock = self.currentBlock
    local currentBlockId = type(currentBlock) == "table" and currentBlock.id or self.lastExecutedBlockId
    if currentBlockId == nil then
        if UOWNativeLog then
            UOWNativeLog("[VPExec] timer complete missing block")
        end
        Debug.Print("Timer complete but no current block")
        return
    end

    self.pendingCompletionWatch = nil

    if UOWNativeLog then
        UOWNativeLog("[VPExec] signalTimerComplete",
            "block=" .. tostring(currentBlockId),
            "remaining=" .. tostring(#self.executionQueue))
    end
    Debug.Print("Timer complete for block " .. currentBlockId)
    
    -- Update block state to completed
    self.blockStates[currentBlockId] = VisualProgrammingInterface.Execution.BlockState.COMPLETED
    local blockWindow = "Block" .. currentBlockId
    if DoesWindowNameExist(blockWindow) then
        Debug.Print("Setting block " .. currentBlockId .. " visual state to completed")
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
        if UOWNativeLog then
            UOWNativeLog("[VPExec] final block complete", "block=" .. tostring(currentBlockId))
        end
        Debug.Print("Last block completed, cleaning up")
        
        -- Keep the final state visible for a moment before resetting
        Debug.Print("Setting up delayed reset")
        self.resetTimer = 0
        self:queueBlocksForReset()
        
        -- Preserve queued reset targets, but stop normal execution immediately.
        self.waitingForTimer = false
        self.isRunning = false
        self.isPaused = false
        self.primingFirstBlock = false
        self.pendingRawDispatch = nil
        self.currentBlock = nil
        self.continueTimer = 0
        
        Debug.Print("Flow execution complete")
        return
    end

    -- The completed block is already recorded above. Clear the live pointer so
    -- the next handoff does not depend on any stale block table state.
    self.currentBlock = nil

    -- Continue execution with next block immediately
    Debug.Print("Continuing execution with " .. #self.executionQueue .. " blocks remaining")
    self:continueExecution()
end
