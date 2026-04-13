-- Main execution system entry point

-- Test flow functionality
local function VPExecSafeString(value)
    local valueType = type(value)
    if valueType == "nil" or valueType == "string" or valueType == "number" or valueType == "boolean" then
        return tostring(value)
    end
    return "<" .. valueType .. ">"
end

function VisualProgrammingInterface.Execution:testFlow()
    -- Hard reset without scheduling delayed stop/reset callbacks that can race the new run
    if type(self.hardResetForTestRun) == "function" then
        self:hardResetForTestRun()
    else
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
    end
    
    if UOWNativeLog then
        UOWNativeLog("[VPExec] testFlow begin")
    end
    Debug.Print("Starting flow test")
    
    -- Initialize test results
    local testResults = {
        blocks = {},
        success = true,
        executionOrder = {}
    }

    -- Check if manager exists and is initialized before touching blocks
    if not VisualProgrammingInterface.manager then
        if UOWNativeLog then
            UOWNativeLog("[VPExec] manager missing")
        end
        self.isRunning = false
        return false, "Manager not initialized"
    end

    if not VisualProgrammingInterface.manager.blocks then
        if UOWNativeLog then
            UOWNativeLog("[VPExec] blocks missing")
        end
        self.isRunning = false
        return false, "No blocks found"
    end
    
    -- Reset execution state
    self.blockStates = {}
    for id, _ in pairs(VisualProgrammingInterface.manager.blocks) do
        self.blockStates[id] = VisualProgrammingInterface.Execution.BlockState.PENDING
    end
    self.waitingForTimer = false
    self.isRunning = false
    
    -- Clear any existing timers
    if VisualProgrammingInterface.ActionTimer then
        Debug.Print("Clearing existing timers before flow test")
        VisualProgrammingInterface.ActionTimer.isWaiting = false
        VisualProgrammingInterface.ActionTimer.callback = nil
        VisualProgrammingInterface.ActionTimer.functionQueue = {}
        VisualProgrammingInterface.ActionTimer.currentQueueId = nil
        VisualProgrammingInterface.ActionTimer.isComplete = false
    end
    
    -- Build execution queue (topological sort)
    local executionQueue = {}
    local visited = {}
    local function visit(block)
        if not block then
            Debug.Print("Warning: Attempted to visit nil block")
            if UOWNativeLog then
                UOWNativeLog("[VPExec] visit nil block")
            end
            return
        end
        if type(block) ~= "table" then
            Debug.Print("Warning: Attempted to visit non-table block: " .. VPExecSafeString(block))
            if UOWNativeLog then
                UOWNativeLog("[VPExec] visit non-table block", VPExecSafeString(block), "type=" .. type(block))
            end
            return
        end
        if block.id == nil then
            Debug.Print("Warning: Attempted to visit block without id")
            if UOWNativeLog then
                UOWNativeLog("[VPExec] visit block missing id", VPExecSafeString(block.type), "y=" .. VPExecSafeString(block.y))
            end
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
        if type(block.connections) == "table" then
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
    for id, block in pairs(VisualProgrammingInterface.manager.blocks) do
        if type(block) == "table" then
            table.insert(sortedBlocks, block)
            if UOWNativeLog then
                UOWNativeLog("[VPExec] sortedBlock candidate", VPExecSafeString(id), VPExecSafeString(block.type), "y=" .. VPExecSafeString(block.y))
            end
        else
            if UOWNativeLog then
                UOWNativeLog("[VPExec] skipping non-table manager entry", VPExecSafeString(id), "type=" .. type(block))
            end
        end
    end
    if UOWNativeLog then
        UOWNativeLog("[VPExec] sortedBlocks", #sortedBlocks)
    end
    table.sort(sortedBlocks, function(a, b) 
        local ay = (type(a) == "table" and tonumber(a.y)) or 0
        local by = (type(b) == "table" and tonumber(b.y)) or 0
        return ay < by
    end)
    
    -- Build execution queue from root blocks first, falling back to all blocks only if needed.
    local rootBlocks = {}
    for _, block in ipairs(sortedBlocks) do
        local hasIncoming = false
        if block and block.id ~= nil then
            for _, otherBlock in ipairs(sortedBlocks) do
                if type(otherBlock) == "table" and type(otherBlock.connections) == "table" then
                    for _, conn in ipairs(otherBlock.connections) do
                        if conn and conn.id == block.id then
                            hasIncoming = true
                            break
                        end
                    end
                end
                if hasIncoming then
                    break
                end
            end
        end
        if not hasIncoming then
            table.insert(rootBlocks, block)
        end
    end
    if UOWNativeLog then
        UOWNativeLog("[VPExec] rootCount", tostring(#rootBlocks))
    end

    local visitList = (#rootBlocks > 0) and rootBlocks or sortedBlocks
    for _, block in ipairs(visitList) do
        if UOWNativeLog then
            UOWNativeLog("[VPExec] visit root", VPExecSafeString(block.id), VPExecSafeString(block.type), "y=" .. VPExecSafeString(block.y), "roots=" .. tostring(#rootBlocks))
        end
        visit(block)
    end
    
    Debug.Print("Built execution queue with " .. #executionQueue .. " blocks")
    if UOWNativeLog then
        UOWNativeLog("[VPExec] built queue", tostring(#executionQueue))
    end
    if UOWNativeLog then
        local labels = {}
        for i, block in ipairs(executionQueue) do
            labels[i] = VPExecSafeString(block.id) .. ":" .. VPExecSafeString(block.type)
        end
        UOWNativeLog("[VPExec] queue", table.concat(labels, ","))
    end
    
    if #executionQueue == 0 then
        if UOWNativeLog then
            UOWNativeLog("[VPExec] built queue empty")
        end
        self.executionQueue = {}
        self.isRunning = false
        return false, "No executable blocks"
    end

    -- Store execution queue for processing in OnUpdate
    self.executionQueue = executionQueue
    self.isRunning = true
    
    -- Execute first block
    if #self.executionQueue > 0 then
        local firstBlock = table.remove(self.executionQueue, 1)
        if UOWNativeLog then
            UOWNativeLog("[VPExec] firstBlock", VPExecSafeString(firstBlock.id), VPExecSafeString(firstBlock.type), "remaining=" .. tostring(#self.executionQueue))
        end
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
            if UOWNativeLog then
                UOWNativeLog("[VPExec] firstBlock failed", VPExecSafeString(firstBlock.id), VPExecSafeString(firstBlock.type))
            end
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
    
    if UOWNativeLog then
        UOWNativeLog("[VPExec] testFlow returning", "queueRemaining=" .. tostring(#self.executionQueue), "waiting=" .. tostring(self.waitingForTimer))
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

-- Check and execute flows based on triggers
function VisualProgrammingInterface.Execution:checkTriggers()
    local triggered, triggerName = VisualProgrammingInterface.Triggers:check()
    if triggered then
        Debug.Print("Trigger detected: " .. triggerName)
        self:start()
    end
end

-- Modified start function to include trigger checks
function VisualProgrammingInterface.Execution:start()
    if self.isRunning then return end
    
    -- Check triggers before starting
    self:checkTriggers()
    
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
        if not block or visited[block.id] then return end
        
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
        local hasIncoming = false
        for _, otherBlock in pairs(VisualProgrammingInterface.manager.blocks) do
            if otherBlock.connections then
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
