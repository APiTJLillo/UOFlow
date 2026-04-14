-- Action Management System for Visual Programming Interface

-- Initialize base Actions system if not already done
VisualProgrammingInterface = VisualProgrammingInterface or {}
VisualProgrammingInterface.Actions = VisualProgrammingInterface.Actions or {
    registry = {},
    defaultParams = {},
    categories = {
        GENERAL = "General",
        COMBAT = "Combat",
        MAGIC = "Magic",
        SKILLS = "Skills",
        ITEMS = "Items",
        MOVEMENT = "Movement",
        TARGETING = "Targeting"
    }
}

-- Parameter type definitions
local ParameterType = {
    NUMBER = "number",
    STRING = "string",
    SELECT = "select",
    BOOLEAN = "boolean"
}

-- Create a parameter definition
function CreateParameter(name, type, defaultValue, options)
    return {
        name = name,
        type = type,
        default = defaultValue,
        options = options, -- For SELECT type: list of possible values
        validate = function(value)
            if type == ParameterType.NUMBER then
                return tonumber(value) ~= nil
            elseif type == ParameterType.SELECT then
                for _, option in ipairs(options or {}) do
                    if option == value then
                        return true
                    end
                end
                return false
            end
            return true
        end
    }
end

local function VPResolveWalkApi()
    if type(UOWInstallLuaMovementWrappers) == "function" then
        UOWInstallLuaMovementWrappers()
    end

    if type(UOFlow) == "table" and type(UOFlow.Walk) == "table" and type(UOFlow.Walk.step) == "function" then
        return UOFlow.Walk
    end

    return nil
end

local VPWalkDirectionMap = {
    north = 0,
    ["north east"] = 1,
    northeast = 1,
    ne = 1,
    east = 2,
    ["south east"] = 3,
    southeast = 3,
    se = 3,
    south = 4,
    ["south west"] = 5,
    southwest = 5,
    sw = 5,
    west = 6,
    ["north west"] = 7,
    northwest = 7,
    nw = 7,
}

local function VPNormalizeWalkDirection(direction)
    local numericDirection = tonumber(direction)
    if numericDirection ~= nil then
        numericDirection = math.floor(numericDirection)
        if numericDirection >= 0 and numericDirection <= 7 then
            return numericDirection
        end
        return nil
    end

    if type(direction) ~= "string" then
        return nil
    end

    local key = string.lower(direction)
    key = string.gsub(key, "_", " ")
    key = string.gsub(key, "%s+", " ")
    key = string.gsub(key, "^%s+", "")
    key = string.gsub(key, "%s+$", "")
    return VPWalkDirectionMap[key]
end

local function VPQueueWalkViaTransport(direction, runFlag, tag)
    local numericDirection = VPNormalizeWalkDirection(direction)
    local numericRun = (runFlag == true or tonumber(runFlag) == 1) and 1 or 0

    if numericDirection == nil then
        if type(UOWNativeLog) == "function" then
            UOWNativeLog(
                "UOFlow.Walk.step invoked",
                "dir=", tostring(direction),
                "run=", tostring(numericRun),
                "source=", tostring(tag),
                "invalid_direction")
        end
        return false, "invalid_direction"
    end

    if type(UOWNativeLog) ~= "function" then
        return false, "native_walk_missing"
    end

    -- Use the same proven evaluator-domain transport line that the DLL already parses.
    UOWNativeLog(
        "UOFlow.Walk.step invoked",
        "dir=", tostring(numericDirection),
        "run=", tostring(numericRun),
        "source=", tostring(tag),
        "helper=", "DummyPrintWalkTransport")
    UOWNativeLog(
        "UOFlow.Walk.step result",
        "dir=", tostring(numericDirection),
        "run=", tostring(numericRun),
        "helper=", "DummyPrintWalkTransport",
        "ok=", "true",
        "msg=", "queued",
        "raw=", "nil")
    return true, "queued"
end

local function VPExecuteWalkStep(params, runFlag)
    local direction = params and params.direction or nil
    local tag = params and params.__vpExecutionTag or "VP:WalkStep"

    if type(UOWNativeLog) == "function" then
        UOWNativeLog("[VPWalk] step begin", tostring(tag), "direction=" .. tostring(direction), "run=" .. tostring(runFlag))
    end

    local ok, msg = VPQueueWalkViaTransport(direction, runFlag and 1 or 0, tag)
    if ok ~= true then
        local walkApi = VPResolveWalkApi()
        if type(walkApi) == "table" and type(walkApi.step) == "function" then
            ok, msg = walkApi.step(direction, runFlag and 1 or 0, tag)
        end
    end

    if type(UOWNativeLog) == "function" then
        UOWNativeLog("[VPWalk] step result", tostring(tag), "ok=" .. tostring(ok), "msg=" .. tostring(msg))
    end

    if ok == true then
        return true, msg or "queued"
    end

    return false, msg or "walk_failed"
end

local VP_SAFE_MOVEMENT_ICON = { texture = "icon000623", x = 5, y = 5 }

-- Register a new action type
function VisualProgrammingInterface.Actions:register(definition)
    if not definition.name then
        Debug.Print("Action definition must have a name")
        return false
    end
    
    -- Set default category if not provided
    definition.category = definition.category or self.categories.GENERAL
    
    -- Create default parameters
    local defaultParams = {}
    for _, param in ipairs(definition.params or {}) do
        defaultParams[param.name] = param.default
    end
    self.defaultParams[definition.name] = defaultParams
    
    -- Store the definition
    self.registry[definition.name] = {
        name = definition.name,
        description = definition.description or "",
        icon = definition.icon or "default",
        params = definition.params or {},
        validate = definition.validate or function() return true end,
        execute = definition.execute or function() return true end,
        category = definition.category
    }
    
    return true
end

-- Get action definition
function VisualProgrammingInterface.Actions:get(name)
    return self.registry[name]
end

-- Get all actions in a category
function VisualProgrammingInterface.Actions:getByCategory(category)
    local actions = {}
    for name, action in pairs(self.registry) do
        if action.category == category then
            actions[name] = action
        end
    end
    return actions
end

-- Get all categories that have actions
function VisualProgrammingInterface.Actions:getActiveCategories()
    local categories = {}
    for _, action in pairs(self.registry) do
        categories[action.category] = true
    end
    
    local result = {}
    for category in pairs(categories) do
        table.insert(result, category)
    end
    table.sort(result)
    return result
end

-- Get default parameters for an action
function VisualProgrammingInterface.Actions:getDefaultParams(name)
    return self.defaultParams[name] or {}
end

-- Validate parameters for an action
function VisualProgrammingInterface.Actions:validateParams(name, params)
    local definition = self:get(name)
    if not definition then return false, "Action not found" end
    
    -- Check required parameters
    for _, paramDef in ipairs(definition.params) do
        local value = params[paramDef.name]
        if value == nil then
            return false, "Missing parameter: " .. paramDef.name
        end
        if not paramDef.validate(value) then
            return false, "Invalid value for parameter: " .. paramDef.name
        end
    end
    
    -- Run action-specific validation
    return definition.validate(params)
end

-- Execute an action
function VisualProgrammingInterface.Actions:execute(name, params)
    local definition = self:get(name)
    if not definition then
        return false, "Action not found"
    end
    
    -- Validate parameters
    local isValid, error = self:validateParams(name, params)
    if not isValid then
        return false, error
    end
    
    -- Execute the action
    return definition.execute(params)
end

-- Initialize action system
function VisualProgrammingInterface.Actions:initialize()
    -- Register movement step actions
    self:register({
        name = "Walk Step",
        description = "Request one walking step in a direction",
        category = self.categories.MOVEMENT,
        icon = VP_SAFE_MOVEMENT_ICON,
        params = {
            CreateParameter("direction", ParameterType.SELECT, "North", 
                {"North", "South", "East", "West", "NorthEast", "NorthWest", "SouthEast", "SouthWest"})
        },
        execute = function(params)
            return VPExecuteWalkStep(params, false)
        end
    })

    self:register({
        name = "Run Step",
        description = "Request one running step in a direction",
        category = self.categories.MOVEMENT,
        icon = VP_SAFE_MOVEMENT_ICON,
        params = {
            CreateParameter("direction", ParameterType.SELECT, "North",
                {"North", "South", "East", "West", "NorthEast", "NorthWest", "SouthEast", "SouthWest"})
        },
        execute = function(params)
            return VPExecuteWalkStep(params, true)
        end
    })

    -- Simple action that prints a message using a chosen destination
    self:register({
        name = "Print Message",
        description = "Output text to console, chat or overhead",
        category = self.categories.GENERAL,
        icon = "Icons/actions/command.dds",
        params = {
            CreateParameter("text", ParameterType.STRING, "Hello"),
            CreateParameter("destination", ParameterType.SELECT, "Console",
                {"Console", "Chat", "Overhead"})
        },
        execute = function(params)
            local dest = params.destination
            if dest == "Chat" then
                local channel = ChatSettings.Channels[SystemData.ChatLogFilters.SAY]
                SendChat(channel, towstring(params.text))
            elseif dest == "Overhead" then
                WindowUtils.SendOverheadText(towstring(params.text), 66, true)
            else
                Debug.Print(tostring(params.text))
            end
            return true
        end
    })


    Debug.Print("Action system initialized")
end

-- Register a new trigger action
function VisualProgrammingInterface.Actions:registerTrigger(definition)
    if not definition.name then
        Debug.Print("Trigger definition must have a name")
        return false
    end
    
    -- Set default category if not provided
    definition.category = definition.category or self.categories.GENERAL
    
    -- Create default parameters
    local defaultParams = {}
    for _, param in ipairs(definition.params or {}) do
        defaultParams[param.name] = param.default
    end
    self.defaultParams[definition.name] = defaultParams
    
    -- Store the definition
    self.registry[definition.name] = {
        name = definition.name,
        description = definition.description or "",
        icon = definition.icon or "default",
        params = definition.params or {},
        validate = definition.validate or function() return true end,
        execute = definition.execute or function() return true end,
        category = definition.category
    }
    
    return true
end

-- Register trigger actions for corpse detection and player health percentage
VisualProgrammingInterface.Actions:registerTrigger({
    name = "Corpse Detection",
    description = "Trigger when a corpse is detected",
    category = VisualProgrammingInterface.Actions.categories.GENERAL,
    icon = "Icons/triggers/corpse_detection.dds",
    params = {
        CreateParameter("radius", ParameterType.NUMBER, "5")
    },
    validate = function(params)
        local radius = tonumber(params.radius)
        return radius and radius >= 1 and radius <= 20
    end,
    execute = function(params)
        -- Corpse detection logic will be implemented later
        return true
    end
})

VisualProgrammingInterface.Actions:registerTrigger({
    name = "Player Health Percentage",
    description = "Trigger when player health falls below a percentage",
    category = VisualProgrammingInterface.Actions.categories.GENERAL,
    icon = "Icons/triggers/player_health.dds",
    params = {
        CreateParameter("percentage", ParameterType.NUMBER, "50")
    },
    validate = function(params)
        local percentage = tonumber(params.percentage)
        return percentage and percentage >= 1 and percentage <= 100
    end,
    execute = function(params)
        -- Player health percentage logic will be implemented later
        return true
    end
})

-- Add error handling and logging for action functions
function VisualProgrammingInterface.Actions:register(definition)
    if not definition.name then
        Debug.Print("Action definition must have a name")
        return false
    end
    
    -- Set default category if not provided
    definition.category = definition.category or self.categories.GENERAL
    
    -- Create default parameters
    local defaultParams = {}
    for _, param in ipairs(definition.params or {}) do
        defaultParams[param.name] = param.default
    end
    self.defaultParams[definition.name] = defaultParams
    
    -- Store the definition
    self.registry[definition.name] = {
        name = definition.name,
        description = definition.description or "",
        icon = definition.icon or "default",
        params = definition.params or {},
        validate = definition.validate or function() return true end,
        execute = definition.execute or function() return true end,
        category = definition.category
    }
    
    return true
end

function VisualProgrammingInterface.Actions:get(name)
    local action = self.registry[name]
    if not action then
        Debug.Print("Action not found: " .. name)
    end
    return action
end

function VisualProgrammingInterface.Actions:validateParams(name, params)
    local definition = self:get(name)
    if not definition then 
        Debug.Print("Action not found: " .. name)
        return false, "Action not found" 
    end
    
    -- Check required parameters
    for _, paramDef in ipairs(definition.params) do
        local value = params[paramDef.name]
        if value == nil then
            Debug.Print("Missing parameter: " .. paramDef.name)
            return false, "Missing parameter: " .. paramDef.name
        end
        if not paramDef.validate(value) then
            Debug.Print("Invalid value for parameter: " .. paramDef.name)
            return false, "Invalid value for parameter: " .. paramDef.name
        end
    end
    
    -- Run action-specific validation
    return definition.validate(params)
end

function VisualProgrammingInterface.Actions:execute(name, params)
    local definition = self:get(name)
    if not definition then
        Debug.Print("Action not found: " .. name)
        return false, "Action not found"
    end
    
    -- Validate parameters
    local isValid, error = self:validateParams(name, params)
    if not isValid then
        Debug.Print("Parameter validation failed: " .. error)
        return false, error
    end
    
    -- Execute the action
    return definition.execute(params)
end

-- Remove any redundant or unused code
function VisualProgrammingInterface.Actions:initialize()
    -- Register movement step actions
    self:register({
        name = "Walk Step",
        description = "Request one walking step in a direction",
        category = self.categories.MOVEMENT,
        icon = VP_SAFE_MOVEMENT_ICON,
        params = {
            CreateParameter("direction", ParameterType.SELECT, "North", 
                {"North", "South", "East", "West", "NorthEast", "NorthWest", "SouthEast", "SouthWest"})
        },
        execute = function(params)
            return VPExecuteWalkStep(params, false)
        end
    })

    self:register({
        name = "Run Step",
        description = "Request one running step in a direction",
        category = self.categories.MOVEMENT,
        icon = VP_SAFE_MOVEMENT_ICON,
        params = {
            CreateParameter("direction", ParameterType.SELECT, "North", 
                {"North", "South", "East", "West", "NorthEast", "NorthWest", "SouthEast", "SouthWest"})
        },
        execute = function(params)
            return VPExecuteWalkStep(params, true)
        end
    })

    -- Simple action that prints a message using a chosen destination
    self:register({
        name = "Print Message",
        description = "Output text to console, chat or overhead",
        category = self.categories.GENERAL,
        icon = "Icons/actions/command.dds",
        params = {
            CreateParameter("text", ParameterType.STRING, "Hello"),
            CreateParameter("destination", ParameterType.SELECT, "Console",
                {"Console", "Chat", "Overhead"})
        },
        execute = function(params)
            local dest = params.destination
            if dest == "Chat" then
                local channel = ChatSettings.Channels[SystemData.ChatLogFilters.SAY]
                SendChat(channel, towstring(params.text))
            elseif dest == "Overhead" then
                WindowUtils.SendOverheadText(towstring(params.text), 66, true)
            else
                Debug.Print(tostring(params.text))
            end
            return true
        end
    })

    Debug.Print("Action system initialized")
end
