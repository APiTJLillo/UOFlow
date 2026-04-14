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

local function VPExecCollectBlocksInVisualOrder(manager)
    local orderedBlocks = {}
    if not manager or type(manager.blocks) ~= "table" then
        return orderedBlocks
    end

    for _, block in pairs(manager.blocks) do
        if type(block) == "table" and block.id ~= nil then
            table.insert(orderedBlocks, block)
        end
    end

    table.sort(orderedBlocks, function(a, b)
        local aRank = (type(a) == "table" and a.column == "right") and 1 or 0
        local bRank = (type(b) == "table" and b.column == "right") and 1 or 0
        if aRank ~= bRank then
            return aRank < bRank
        end

        local ay = tonumber(a and a.y) or 0
        local by = tonumber(b and b.y) or 0
        if ay ~= by then
            return ay < by
        end

        return (tonumber(a and a.id) or 0) < (tonumber(b and b.id) or 0)
    end)

    return orderedBlocks
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
    local orderedBlocks = VPExecCollectBlocksInVisualOrder(manager)

    for _, block in ipairs(orderedBlocks) do
        local id = block and block.id
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
    local orderedList = orderedRecords or {}
    local rootCount = (#orderedList > 0) and 1 or 0

    if UOWNativeLog then
        UOWNativeLog("[VPExec] rootCount", tostring(rootCount))
    end

    if rootCount > 0 and UOWNativeLog then
        local firstRecord = orderedList[1]
        UOWNativeLog("[VPExec] visit root",
            VPExecSafeString(firstRecord and firstRecord.id),
            VPExecSafeString(firstRecord and firstRecord.type),
            "y=" .. VPExecSafeString(firstRecord and firstRecord.y),
            "roots=1")
    end

    for _, record in ipairs(orderedList) do
        if type(record) == "table" and record.id ~= nil then
            local liveBlock = self:resolveBlockById(record.id)
            if type(liveBlock) == "table" then
                table.insert(executionQueue, liveBlock)
            else
                if UOWNativeLog then
                    UOWNativeLog("[VPExec] live block missing", VPExecSafeString(record.id), VPExecSafeString(record.type))
                end
            end
        else
            if UOWNativeLog then
                UOWNativeLog("[VPExec] visit invalid record", VPExecSafeString(record))
            end
        end
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
    
    local executionQueue = {}
    local manager = VisualProgrammingInterface.manager
    local orderedBlocks = {}
    if manager and type(manager.getBlocksInVisualOrder) == "function" then
        orderedBlocks = manager:getBlocksInVisualOrder()
    else
        orderedBlocks = VPExecCollectBlocksInVisualOrder(manager)
    end

    if UOWNativeLog then
        UOWNativeLog("[VPExec] live queue source", "count=" .. tostring(#orderedBlocks))
    end

    for _, block in ipairs(orderedBlocks) do
        if type(block) == "table" and block.id ~= nil then
            table.insert(executionQueue, block)
            if UOWNativeLog then
                UOWNativeLog("[VPExec] live queue block",
                    VPExecSafeString(block.id),
                    VPExecSafeString(block.type),
                    "y=" .. VPExecSafeString(block.y))
            end
        end
    end

    local queueCount = #executionQueue
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
    self.primingFirstBlock = false
    self.isRunning = true
    self.isPaused = false
    self.currentBlock = nil
    self.continueTimer = 0
    self.waitingForTimer = false

    local executeFn = self.executeBlock or VisualProgrammingInterface.Execution.executeBlock
    local firstBlock = self.executionQueue[1]
    if type(executeFn) ~= "function" then
        self.executionQueue = {}
        self.isRunning = false
        if UOWNativeLog then
            UOWNativeLog("[VPExec] kickoff failed", "execute_handler_missing")
        end
        return false, "execute_handler_missing"
    end

    if type(firstBlock) ~= "table" or firstBlock.id == nil then
        self.executionQueue = {}
        self.isRunning = false
        if UOWNativeLog then
            UOWNativeLog("[VPExec] kickoff failed", "missing_first_block")
        end
        return false, "missing_first_block"
    end

    if UOWNativeLog then
        UOWNativeLog("[VPExec] kickoff",
            "queue=" .. tostring(#self.executionQueue),
            "first=" .. tostring(firstBlock.id),
            "type=" .. tostring(firstBlock.type))
    end

    executeFn(self, firstBlock)

    if UOWNativeLog then
        UOWNativeLog("[VPExec] kickoff dispatched",
            "remaining=" .. tostring(#self.executionQueue),
            "waiting=" .. tostring(self.waitingForTimer),
            "current=" .. tostring(self.currentBlock and self.currentBlock.id or nil))
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

    local snapshotByKey, orderedRecords, snapshotErr = self:buildExecutionSnapshot()
    if not snapshotByKey then
        Debug.Print("Error: Could not build execution queue: " .. tostring(snapshotErr or "unknown"))
        return false
    end

    self:buildExecutionQueueFromSnapshot(snapshotByKey, orderedRecords, self.executionQueue)
    if #self.executionQueue == 0 then
        Debug.Print("Error: Could not find starting block")
        return false
    end
    
    -- Start execution timer
    self:continueExecution()
end
