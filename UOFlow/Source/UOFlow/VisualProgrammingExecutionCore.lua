-- Core execution state and initialization
VisualProgrammingInterface.Execution = {
    isRunning = false,
    isPaused = false,
    currentBlock = nil,
    executionQueue = {},
    blockStates = {}, -- Stores execution state for each block
    delay = 100, -- Reduced delay between blocks for smoother execution
    waitingForTimer = false -- New flag to track timer state
}

-- Block execution states
VisualProgrammingInterface.Execution.BlockState = {
    PENDING = "pending",
    RUNNING = "running",
    COMPLETED = "completed",
    ERROR = "error"
}

    -- Initialize execution system
    function VisualProgrammingInterface.Execution:initialize()
        -- Register as a completion callback with the ActionTimer
        local self = VisualProgrammingInterface.Execution
        VisualProgrammingInterface.ActionTimer:registerCompletionCallback(
            "execution",
            function()
                if self.signalTimerComplete then
                    Debug.Print("Timer completion callback triggered")
                    self:signalTimerComplete()
                end
            end
        )
        
        -- Initialize timer variables with shorter delays for smoother execution
        VisualProgrammingInterface.Execution.resetTimer = 0
        VisualProgrammingInterface.Execution.continueTimer = 0
        VisualProgrammingInterface.Execution.resetBlockIds = {}
        VisualProgrammingInterface.Execution.resetDelay = 1000 -- Reduced reset delay for smoother transitions
        VisualProgrammingInterface.Execution.delay = 100 -- Ensure delay is set for block transitions
        
        Debug.Print("Execution system initialized with delay: " .. VisualProgrammingInterface.Execution.delay .. "ms")
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
