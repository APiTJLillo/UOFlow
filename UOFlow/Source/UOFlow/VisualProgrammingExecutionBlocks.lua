-- Block execution and state management
function VisualProgrammingInterface.Execution:executeBlock(block)
    if not block then return false end
    
    if UOWNativeLog then
        UOWNativeLog("[VPExec] executeBlock", tostring(block.id), tostring(block.type))
    end
    Debug.Print("Executing block " .. block.type .. " [" .. block.id .. "]")
    
    -- Update block state
    self.blockStates[block.id] = VisualProgrammingInterface.Execution.BlockState.RUNNING
    self.currentBlock = block
    
    -- Update visual state
    local blockWindow = "Block" .. block.id
    if DoesWindowNameExist(blockWindow) then
        WindowSetTintColor(blockWindow, 255, 255, 0) -- Yellow during execution
    end
    
    -- Check if Actions system is properly initialized
    if not VisualProgrammingInterface.Actions or type(VisualProgrammingInterface.Actions.get) ~= "function" then
        Debug.Print("Error: Actions system not properly initialized")
        self.blockStates[block.id] = VisualProgrammingInterface.Execution.BlockState.ERROR
        if DoesWindowNameExist(blockWindow) then
            WindowSetTintColor(blockWindow, 255, 0, 0) -- Red for error
        end
        return false
    end

    -- Get action definition
    local success = true
    local action = VisualProgrammingInterface.Actions:get(block.type)
    if not action then
        if UOWNativeLog then
            UOWNativeLog("[VPExec] action lookup failed", tostring(block.id), tostring(block.type), tostring(action))
        end
        self.blockStates[block.id] = VisualProgrammingInterface.Execution.BlockState.ERROR
        if DoesWindowNameExist(blockWindow) then
            WindowSetTintColor(blockWindow, 255, 0, 0) -- Red for error
        end
        Debug.Print("Unknown action type: " .. block.type)
        return false
    end
    
    -- Validate parameters
    if type(VisualProgrammingInterface.Actions.validateParams) ~= "function" then
        Debug.Print("Error: validateParams not available")
        self.blockStates[block.id] = VisualProgrammingInterface.Execution.BlockState.ERROR
        if DoesWindowNameExist(blockWindow) then
            WindowSetTintColor(blockWindow, 255, 0, 0) -- Red for error
        end
        return false
    end
    
    local result = nil
    success, result = VisualProgrammingInterface.Actions:validateParams(block.type, block.params)
    
    if not success then
        if UOWNativeLog then
            UOWNativeLog("[VPExec] validate failed", tostring(block.id), tostring(block.type), "ok=" .. tostring(success), "result=" .. tostring(result))
        end
        self.blockStates[block.id] = VisualProgrammingInterface.Execution.BlockState.ERROR
        if DoesWindowNameExist(blockWindow) then
            WindowSetTintColor(blockWindow, 255, 0, 0) -- Red for error
        end
        Debug.Print("Parameter validation failed: " .. tostring(result))
        return false
    end
    
    -- Execute action
    if type(VisualProgrammingInterface.Actions.execute) ~= "function" then
        Debug.Print("Error: execute not available")
        self.blockStates[block.id] = VisualProgrammingInterface.Execution.BlockState.ERROR
        if DoesWindowNameExist(blockWindow) then
            WindowSetTintColor(blockWindow, 255, 0, 0) -- Red for error
        end
        return false
    end
    
    -- Set waiting flag before execution
    self.waitingForTimer = true
    
    local runtimeParams = {}
    for key, value in pairs(block.params or {}) do
        runtimeParams[key] = value
    end
    runtimeParams.__vpBlockId = block.id
    runtimeParams.__vpBlockType = block.type
    runtimeParams.__vpExecutionTag = "VP:block=" .. tostring(block.id) .. ":type=" .. tostring(block.type)

    Debug.Print("Executing action for block " .. block.id)
    success, result = VisualProgrammingInterface.Actions:execute(block.type, runtimeParams)
    if UOWNativeLog then
        UOWNativeLog("[VPExec] action returned", tostring(block.id), tostring(block.type), "ok=" .. tostring(success), "result=" .. tostring(result), "timerWaiting=" .. tostring(VisualProgrammingInterface.ActionTimer.isWaiting))
    end

    local timerStarted = VisualProgrammingInterface.ActionTimer and VisualProgrammingInterface.ActionTimer.isWaiting

    if not success and timerStarted then
        if UOWNativeLog then
            UOWNativeLog("[VPExec] action promoted to async success", tostring(block.id), tostring(block.type), "result=" .. tostring(result))
        end
        Debug.Print("Action entered async wait; treating as started")
        success = true
    end

    -- If no timer was started or ActionTimer doesn't exist, clear the waiting flag
    if not timerStarted then
        Debug.Print("No timer started for " .. block.type .. " [" .. block.id .. "]")
        self.waitingForTimer = false
    else
        Debug.Print("Timer started for " .. block.type .. " [" .. block.id .. "]")
    end
    
    -- Update block state based on execution result
    if success then
        if not self.waitingForTimer then
            if UOWNativeLog then
                UOWNativeLog("[VPExec] immediate completion", tostring(block.id), tostring(block.type))
            end
            Debug.Print("Block " .. block.type .. " [" .. block.id .. "] completed immediately")
            self.blockStates[block.id] = VisualProgrammingInterface.Execution.BlockState.COMPLETED
            if DoesWindowNameExist(blockWindow) then
                WindowSetTintColor(blockWindow, 0, 255, 0) -- Green for success
            end
            -- Don't clear timers for immediate completion
            -- Let the timer system handle its own state
        end
    else
        if UOWNativeLog then
            UOWNativeLog("[VPExec] block execution error", tostring(block.id), tostring(block.type), tostring(result))
        end
        Debug.Print("Block " .. block.type .. " [" .. block.id .. "] failed: " .. tostring(result))
        self.blockStates[block.id] = VisualProgrammingInterface.Execution.BlockState.ERROR
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
            error = result
        }
        Debug.Print("Block execution error: " .. tostring(result))
        Debug.Print("Error details: " .. table.concat({
            "Block: " .. tostring(errorInfo.blockType) .. " [" .. tostring(errorInfo.blockId) .. "]",
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

-- Queue blocks for reset
function VisualProgrammingInterface.Execution:queueBlocksForReset()
    Debug.Print("Queueing blocks for reset")
    VisualProgrammingInterface.Execution.resetBlockIds = {}
    if not VisualProgrammingInterface.manager or type(VisualProgrammingInterface.manager.blocks) ~= "table" then
        Debug.Print("Reset queue skipped: manager.blocks missing")
        return
    end
    -- Queue all blocks for reset
    for id, _ in pairs(VisualProgrammingInterface.manager.blocks) do
        local block = VisualProgrammingInterface.manager.blocks[id]
        if type(block) == "table" then
            Debug.Print("- Queueing " .. tostring(block.type) .. " [" .. tostring(id) .. "]")
            table.insert(VisualProgrammingInterface.Execution.resetBlockIds, id)
        end
    end
    -- Reset timer for delayed reset
    VisualProgrammingInterface.Execution.resetTimer = 0
    Debug.Print("Reset queue initialized with " .. #VisualProgrammingInterface.Execution.resetBlockIds .. " blocks")
end
