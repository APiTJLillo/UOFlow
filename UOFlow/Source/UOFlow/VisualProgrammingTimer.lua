Timer = {}
Timer.__index = Timer

function Timer:new()
    local timer = {
        currentTime = 0,
        targetTime = 0,
        isWaiting = false,
        callback = nil,
        functionQueue = {},
        currentQueueId = nil,
        isComplete = false,
        completionCallbacks = {}
    }
    setmetatable(timer, Timer)
    return timer
end

function Timer:registerCompletionCallback(callbackName, callback)
    self.completionCallbacks[callbackName] = callback
    Debug.Print("Registered completion callback: " .. callbackName)
end

function Timer:notifyCompletion()
    Debug.Print("Notifying completion callbacks")
    if next(self.completionCallbacks) == nil then
        Debug.Print("No completion callbacks registered")
        return
    end
    
    for callbackName, callback in pairs(self.completionCallbacks) do
        Debug.Print("Executing callback: " .. callbackName)
        local success, err = pcall(callback)
        if not success then
            Debug.Print("Warning: Callback " .. callbackName .. " failed: " .. tostring(err))
        else
            Debug.Print("Callback " .. callbackName .. " executed successfully")
        end
    end
end

function Timer:hasCompletionCallbacks()
    return next(self.completionCallbacks) ~= nil
end

function Timer:reset()
    Debug.Print("Resetting timer")
    self.isWaiting = false
    self.callback = nil
    self.functionQueue = {}
    self.currentQueueId = nil
    self.isComplete = false
    self.currentTime = 0
    self.targetTime = 0
    -- Don't clear completion callbacks on reset
    -- self.completionCallbacks remains intact
end

function Timer:OnUpdate(timePassed)
    if not self.isWaiting then return end

    -- Ensure timePassed is valid
    if type(timePassed) ~= "number" or timePassed <= 0 then
        Debug.Print("Warning: Invalid timePassed value: " .. tostring(timePassed))
        return
    end

    self.currentTime = self.currentTime + timePassed
    
    if self.currentTime >= self.targetTime then
        local callback = self.callback
        local currentQueueId = self.currentQueueId -- Store for logging
        self.currentTime = 0
        
        if callback then
            local success, isComplete = pcall(callback)
            Debug.Print("Timer callback executed - Queue: " .. tostring(currentQueueId) .. 
                       ", Success: " .. tostring(success) .. 
                       ", Complete: " .. tostring(isComplete))
            
            if success then
                if isComplete then
                    -- Process next queued function
                    if #self.functionQueue > 0 then
                        local nextFunc = table.remove(self.functionQueue, 1)
                        if nextFunc.duration and nextFunc.callback then
                            Debug.Print("Starting next queued timer - Duration: " .. nextFunc.duration .. 
                                      "ms, Queue: " .. tostring(nextFunc.queueId))
                            -- Validate next function parameters
                            if type(nextFunc.duration) ~= "number" or nextFunc.duration <= 0 then
                                Debug.Print("Warning: Invalid duration in queued function: " .. tostring(nextFunc.duration))
                                self:reset()
                                return
                            end
                            if type(nextFunc.callback) ~= "function" then
                                Debug.Print("Warning: Invalid callback in queued function")
                                self:reset()
                                return
                            end
                            
                            -- Start next timer
                            self.currentTime = 0
                            self.targetTime = nextFunc.duration / 1000
                            self.callback = nextFunc.callback
                            self.currentQueueId = nextFunc.queueId
                            self.isComplete = false
                            return
                        else
                            Debug.Print("Warning: Invalid queued function, skipping")
                        end
                    end
                    
                    -- Reset timer state but don't notify completion
                    -- Let the action handle its own completion notification
                    Debug.Print("No more queued functions, resetting timer")
                    self:reset()
                else
                    Debug.Print("Timer callback not complete, continuing current timer")
                end
            else
                Debug.Print("Timer callback failed: " .. tostring(isComplete))
                self:notifyCompletion()
                self:reset()
            end
        else
            Debug.Print("No callback found for timer, resetting")
            self:reset()
        end
    end
end

function Timer:start(duration, callback, queueId)
    Debug.Print("Starting timer: duration = " .. duration .. "ms, queueId = " .. tostring(queueId))
    
    -- Validate parameters
    if type(duration) ~= "number" or duration <= 0 then
        Debug.Print("Warning: Invalid duration: " .. tostring(duration))
        return
    end
    if type(callback) ~= "function" then
        Debug.Print("Warning: Invalid callback")
        return
    end
    
    -- If timer is already waiting, queue this function
    if self.isWaiting then
        Debug.Print("Timer busy, queueing function with id: " .. tostring(queueId))
        table.insert(self.functionQueue, {
            duration = duration,
            callback = callback,
            queueId = queueId
        })
        return
    end
    
    -- Start timer with provided parameters
    Debug.Print("Starting new timer with id: " .. tostring(queueId))
    self.currentTime = 0
    self.targetTime = duration / 1000
    self.isWaiting = true
    self.callback = callback
    self.currentQueueId = queueId
    self.isComplete = false
end

-- Ensure the OnUpdate method is called with the correct self reference
function Timer:initialize()
    local selfReference = self
    local function onUpdateWrapper(timePassed)
        selfReference:OnUpdate(timePassed)
    end
    RegisterEventHandler(SystemData.Events.UPDATE_PROCESSED, onUpdateWrapper)
end

-- Initialize the timer
local actionTimer = Timer:new()
actionTimer:initialize()
VisualProgrammingInterface.ActionTimer = actionTimer
