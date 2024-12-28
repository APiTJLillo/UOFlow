-- Main entry point for Visual Programming Interface
VisualProgrammingInterface = {}

-- Actions system
VisualProgrammingInterface.Actions = {
    actions = {},
    categories = {},
    
    initialize = function(self)
        Debug.Print("Initializing Actions system")
        -- Add default categories
        self.categories = {
            "Basic",
            "Combat",
            "Movement",
            "Targeting"
        }
        
        -- Add default actions
        -- Add Move action with direction dropdown
        self:registerAction("Move", {
            category = "Movement",
            description = "Move in specified direction",
            params = {
                {
                    name = "direction",
                    type = "select",
                    options = {"North", "South", "East", "West", "NorthEast", "NorthWest", "SouthEast", "SouthWest"},
                    default = "North"
                },
                {
                    name = "distance",
                    type = "number",
                    default = 1,
                    validate = function(value)
                        return value >= 1 and value <= 20
                    end
                }
            }
        })

        self:registerAction("Wait", {
            category = "Basic",
            description = "Wait for specified time",
            params = {
                {
                    name = "time",
                    type = "number",
                    default = 1000,
                    validate = function(value)
                        return value >= 0 and value <= 10000
                    end
                }
            }
        })
        
        self:registerAction("Cast Spell", {
            category = "Combat",
            description = "Cast a selected spell",
            params = {
                {
                    name = "spellId",
                    type = "number",
                    default = 1,
                    validate = function(value)
                        return value >= 1 and value <= 100
                    end
                }
            }
        })
        
        self:registerAction("Heal Self", {
            category = "Combat",
            description = "Cast healing on yourself",
            params = {
                {
                    name = "wait",
                    type = "boolean",
                    default = true
                }
            }
        })
        
        Debug.Print("Actions system initialized")
    end,
    
    registerAction = function(self, name, definition)
        self.actions[name] = definition
    end,
    
    get = function(self, name)
        return self.actions[name]
    end,
    
    getActiveCategories = function(self)
        return self.categories
    end,
    
    getByCategory = function(self, category)
        local result = {}
        for name, action in pairs(self.actions) do
            if action.category == category then
                result[name] = action
            end
        end
        return result
    end
}

-- Global initialization
function Initialize()
    Debug.Print("Global initialization of Visual Programming Interface")
    VisualProgrammingInterface.Initialize()
end

-- Initialize all subsystems
function VisualProgrammingInterface.Initialize()
    Debug.Print("Initializing Visual Programming Interface")
    
    -- Initialize Actions system
    VisualProgrammingInterface.Actions:initialize()
    
    -- Initialize manager last
    if VisualProgrammingInterface.manager then
        VisualProgrammingInterface.manager:initialize()
    end
    
    -- Set window title
    LabelSetText("VisualProgrammingInterfaceWindow_UO_TitleBar_WindowTitle", StringToWString("Visual Programming Interface"))
    
    Debug.Print("Visual Programming Interface initialized")
end

-- Hide interface
function VisualProgrammingInterface.Hide()
    WindowSetShowing("VisualProgrammingInterfaceWindow", false)
end
