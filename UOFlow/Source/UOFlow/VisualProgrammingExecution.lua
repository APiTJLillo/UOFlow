-- Main execution system entry point

-- Test flow functionality
local function VPExecSafeString(value)
    local valueType = type(value)
    if valueType == "nil" or valueType == "string" or valueType == "number" or valueType == "boolean" then
        return tostring(value)
    end
    return "<" .. valueType .. ">"
end

local function VPExecNormalizeId(value)
    if value == nil then
        return nil
    end
    return tostring(value)
end

local function VPExecSnapshotConnectionIds(block)
    local ids = {}
    if type(block) ~= "table" or type(block.connections) ~= "table" then
        return ids
    end

    for _, connection in ipairs(block.connections) do
        local connectionId = nil
        if type(connection) == "table" then
            connectionId = connection.id
        elseif type(connection) == "number" or type(connection) == "string" then
            connectionId = connection
        end

        local key = VPExecNormalizeId(connectionId)
        if key then
            table.insert(ids, key)
        end
    end

    return ids
end

local function VPExecCompareRecords(a, b)
    local ay = tonumber(a and a.y) or 0
    local by = tonumber(b and b.y) or 0
    if ay ~= by then
        return ay < by
    end
    return VPExecSafeString(a and a.key) < VPExecSafeString(b and b.key)
end

function VisualProgrammingInterface.Execution:resolveBlockById(blockId)
    local manager = VisualProgrammingInterface.manager
    if not manager or type(manager.blocks) ~= "table" then
        return nil
    end

    local directBlock = manager.blocks[blockId]
    if type(directBlock) == "table" then
        return directBlock
    end

    if type(manager.getBlock) == "function" then
        local managerBlock = manager:getBlock(blockId)
        if type(managerBlock) == "table" then
            return managerBlock
        end
    end

    local targetKey = VPExecNormalizeId(blockId)
    for _, block in pairs(manager.blocks) do
        if type(block) == "table" and VPExecNormalizeId(block.id) == targetKey then
            return block
        end
    end

    return nil
end

function VisualProgrammingInterface.Execution:buildExecutionSnapshot()
    local manager = VisualProgrammingInterface.manager
    if not manager or type(manager.blocks) ~= "table" then
        return nil, nil, "No blocks found"
    end

    local snapshotByKey = {}
    local orderedRecords = {}

    for id, block in pairs(manager.blocks) do
        if type(block) == "table" and block.id ~= nil then
            local key = VPExecNormalizeId(block.id)
            local record = {
                id = block.id,
                key = key,
                type = block.type,
                y = tonumber(block.y) or 0,
                connectionIds = VPExecSnapshotConnectionIds(block)
            }
            snapshotByKey[key] = record
            table.insert(orderedRecords, record)
            if UOWNativeLog then
                UOWNativeLog("[VPExec] sortedBlock candidate", VPExecSafeString(record.id), VPExecSafeString(record.type), "y=" .. VPExecSafeString(record.y))
            end
        else
            if UOWNativeLog then
                UOWNativeLog("[VPExec] skipping invalid manager entry", VPExecSafeString(id), "type=" .. type(block))
            end
        end
    end

    table.sort(orderedRecords, VPExecCompareRecords)
    if UOWNativeLog then
        UOWNativeLog("[VPExec] sortedBlocks", #orderedRecords)
    end

    return snapshotByKey, orderedRecords, nil
end

function VisualProgrammingInterface.Execution:buildExecutionQueueFromSnapshot(snapshotByKey, orderedRecords, executionQueue)
    executionQueue = type(executionQueue) == "table" and executionQueue or {}
    local visited = {}
    local rootRecords = {}

    for _, record in ipairs(orderedRecords or {}) do
        local hasIncoming = false
        for _, otherRecord in ipairs(orderedRecords or {}) do
            for _, connectionKey in ipairs(otherRecord.connectionIds or {}) do
                if connectionKey == record.key then
                    hasIncoming = true
                    break
                end
            end
            if hasIncoming then
                break
            end
        end
        if not hasIncoming then
            table.insert(rootRecords, record)
        end
    end

    if UOWNativeLog then
        UOWNativeLog("[VPExec] rootCount", tostring(#rootRecords))
    end

    local visitList = (#rootRecords > 0) and rootRecords or (orderedRecords or {})

    local function visitRecord(record)
        if type(record) ~= "table" or not record.key then
            if UOWNativeLog then
                UOWNativeLog("[VPExec] visit invalid record", VPExecSafeString(record))
            end
            return
        end
        if visited[record.key] then
            return
        end
        visited[record.key] = true

        local liveBlock = self:resolveBlockById(record.id)
        if type(liveBlock) == "table" then
            table.insert(executionQueue, liveBlock)
        else
            if UOWNativeLog then
                UOWNativeLog("[VPExec] live block missing", VPExecSafeString(record.id), VPExecSafeString(record.type))
            end
        end

        for _, connectionKey in ipairs(record.connectionIds or {}) do
            local nextRecord = snapshotByKey[connectionKey]
            if nextRecord then
                visitRecord(nextRecord)
            else
                if UOWNativeLog then
                    UOWNativeLog("[VPExec] missing snapshot connection", VPExecSafeString(record.id), "to=" .. VPExecSafeString(connectionKey))
                end
            end
        end
    end

    for _, record in ipairs(visitList) do
        if UOWNativeLog then
            UOWNativeLog("[VPExec] visit root", VPExecSafeString(record.id), VPExecSafeString(record.type), "y=" .. VPExecSafeString(record.y), "roots=" .. tostring(#rootRecords))
        end
        visitRecord(record)
    end

    if UOWNativeLog then
        UOWNativeLog("[VPExec] built queue", tostring(#executionQueue))
    end

    return #executionQueue
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
    
    local snapshotByKey, orderedRecords, snapshotErr = self:buildExecutionSnapshot()
    if not snapshotByKey then
        if UOWNativeLog then
            UOWNativeLog("[VPExec] snapshot error", VPExecSafeString(snapshotErr))
        end
        self.executionQueue = {}
        self.isRunning = false
        return false, snapshotErr or "No executable blocks"
    end

    local executionQueue = {}
    local queueCount = self:buildExecutionQueueFromSnapshot(snapshotByKey, orderedRecords, executionQueue)
    if type(queueCount) ~= "number" then
        queueCount = 0
    end
    if UOWNativeLog then
        UOWNativeLog("[VPExec] post build queue", "count=" .. tostring(queueCount), "type=" .. type(executionQueue))
    end

    if queueCount == 0 then
        if UOWNativeLog then
            UOWNativeLog("[VPExec] built queue empty")
        end
        self.executionQueue = {}
        self.isRunning = false
        return false, "No executable blocks"
    end

    -- Store execution queue for processing in OnUpdate
    self.executionQueue = executionQueue
    if UOWNativeLog then
        UOWNativeLog("[VPExec] queue stored", tostring(#self.executionQueue))
    end
        self.primingFirstBlock = true
        self.isRunning = true
        if UOWNativeLog then
            UOWNativeLog("[VPExec] isRunning", tostring(self.isRunning), "priming=" .. tostring(self.primingFirstBlock))
        end

    -- Execute first block
    if #self.executionQueue > 0 then
        if UOWNativeLog then
            UOWNativeLog("[VPExec] remove first pending", tostring(#self.executionQueue))
        end
        local firstBlock = table.remove(self.executionQueue, 1)
        if type(firstBlock) ~= "table" then
            if UOWNativeLog then
                UOWNativeLog("[VPExec] firstBlock invalid", "type=" .. type(firstBlock))
            end
            self.isRunning = false
            return false, "Invalid first block"
        end
        if UOWNativeLog then
            UOWNativeLog("[VPExec] firstBlock", VPExecSafeString(firstBlock.id), VPExecSafeString(firstBlock.type), "remaining=" .. tostring(#self.executionQueue))
        end
        table.insert(testResults.executionOrder, firstBlock.id)

        self.primingFirstBlock = false
        if UOWNativeLog then
            UOWNativeLog("[VPExec] priming cleared before firstBlock", VPExecSafeString(firstBlock.id), VPExecSafeString(firstBlock.type))
        end

        local success = self:executeBlock(firstBlock)
        self.primingFirstBlock = false
        if UOWNativeLog then
            UOWNativeLog("[VPExec] firstBlock done", VPExecSafeString(firstBlock.id), "success=" .. tostring(success), "waiting=" .. tostring(self.waitingForTimer), "remaining=" .. tostring(#self.executionQueue))
        end
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

        if not self.waitingForTimer then
            if UOWNativeLog then
                UOWNativeLog("[VPExec] firstBlock continue immediate", "remaining=" .. tostring(#self.executionQueue))
            end
            self:continueExecution()
        end
    end

    self.primingFirstBlock = false
    
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
